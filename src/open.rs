//! The remote side: send open requests down $SSH_AUTH_SOCK, which ssh has
//! forwarded back to the vs-connect daemon on the local machine.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::proto::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOptions {
    pub window: WindowMode,
    /// -g: parse path:line[:col] even when a file with the literal colon
    /// name exists (that parse is otherwise the default only for names that
    /// don't exist as-is).
    pub force_goto: bool,
    pub diff: Option<(String, String)>,
    /// Block until the editor is closed (`code --wait`); over the channel
    /// this requires a single path or --diff.
    pub wait: bool,
    pub paths: Vec<String>,
}

pub fn run(opts: OpenOptions) -> Result<()> {
    if let Some(cli) = vscode_terminal_cli() {
        return exec_real_cli(&cli, &to_cli_args(&opts));
    }
    send_plan(opts)
}

/// Reconstruct real-CLI argv from parsed options (for deferring to VS
/// Code's own CLI inside its terminals).
fn to_cli_args(opts: &OpenOptions) -> Vec<String> {
    let mut v = Vec::new();
    match opts.window {
        WindowMode::New => v.push("--new-window".into()),
        WindowMode::Reuse => v.push("--reuse-window".into()),
        WindowMode::Default => {}
    }
    if opts.force_goto {
        v.push("--goto".into());
    }
    if opts.wait {
        v.push("--wait".into());
    }
    if let Some((l, r)) = &opts.diff {
        v.push("--diff".into());
        v.push(l.clone());
        v.push(r.clone());
    }
    v.extend(opts.paths.iter().cloned());
    v
}

/// Invoked via a symlink named `code`. Precedence: VS Code's own remote CLI
/// (its terminals), then a live vs-connect channel (remote ssh sessions),
/// then the machine's real VS Code — so on a desktop that also gets remoted
/// into, `code` keeps behaving exactly like the real thing in person.
pub fn run_as_code_shim(args: Vec<String>) -> Result<()> {
    if let Some(cli) = vscode_terminal_cli() {
        return exec_real_cli(&cli, &args);
    }
    if channel_is_vs_connect() {
        return send_plan(parse_shim_args(args)?);
    }
    if in_ssh_session() {
        // A broken channel in an ssh session: launching a local (likely
        // headless) VS Code here would be far more confusing than an error.
        bail!(
            "no vs-connect channel in this ssh session — is the daemon running on your local \
             machine, and was this session opened after it started? `vs-connect status` has \
             details."
        );
    }
    match find_local_code() {
        Some(code) => exec_real_cli(&code, &args),
        None => bail!("no VS Code installation found on this machine (looked through PATH)"),
    }
}

/// True when $SSH_AUTH_SOCK answers as a vs-connect daemon.
fn channel_is_vs_connect() -> bool {
    let Some(sock) = std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()) else {
        return false;
    };
    matches!(crate::daemon::ping(Path::new(&sock)), Ok(Some(_)))
}

fn in_ssh_session() -> bool {
    ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty()))
}

/// The machine's real `code`, skipping ourselves and any other vs-connect
/// symlink so the shim can never recurse into itself.
fn find_local_code() -> Option<PathBuf> {
    let self_exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok());
    let is_vs_connect = |p: &Path| match p.canonicalize() {
        Ok(c) => {
            Some(&c) == self_exe.as_ref()
                || c.file_name().is_some_and(|n| n == "vs-connect")
        }
        Err(_) => true, // unresolvable → not launchable anyway
    };

    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("code");
            if candidate.is_file() && !is_vs_connect(&candidate) {
                return Some(candidate);
            }
        }
    }
    // Installs that aren't on PATH.
    let mut fallbacks = vec![PathBuf::from(
        "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
    )];
    if let Some(home) = std::env::var_os("HOME") {
        fallbacks.push(
            PathBuf::from(home)
                .join("Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"),
        );
    }
    fallbacks.into_iter().find(|p| p.is_file())
}

fn parse_shim_args(args: Vec<String>) -> Result<OpenOptions> {
    let mut opts = OpenOptions {
        window: WindowMode::Default,
        force_goto: false,
        diff: None,
        wait: false,
        paths: Vec::new(),
    };
    let mut diff_flag = false;
    for a in args {
        match a.as_str() {
            "-n" | "--new-window" => opts.window = WindowMode::New,
            "-r" | "--reuse-window" => opts.window = WindowMode::Reuse,
            "-g" | "--goto" => opts.force_goto = true,
            "-d" | "--diff" => diff_flag = true,
            "-w" | "--wait" => opts.wait = true,
            s if s.starts_with('-') => bail!(
                "unsupported flag {s} over vs-connect (supported: -n/--new-window, \
                 -r/--reuse-window, -g/--goto, -d/--diff, -w/--wait)"
            ),
            _ => opts.paths.push(a),
        }
    }
    if diff_flag {
        if opts.paths.len() != 2 {
            bail!("--diff needs exactly two files");
        }
        let right = opts.paths.pop().expect("checked len");
        let left = opts.paths.pop().expect("checked len");
        opts.diff = Some((left, right));
    }
    if opts.diff.is_none() && opts.paths.is_empty() {
        bail!("usage: code [-n|-r] [-g] <path[:line[:col]]>...  |  code -d <left> <right>");
    }
    Ok(opts)
}

fn send_plan(opts: OpenOptions) -> Result<()> {
    if opts.wait && opts.diff.is_none() && opts.paths.len() != 1 {
        // Sequential per-path requests would wait for each file before
        // opening the next — not "open all, wait for all". Refuse rather
        // than ship the wrong semantics.
        bail!("over vs-connect, --wait supports exactly one path (or --diff)");
    }
    let sock = std::env::var("SSH_AUTH_SOCK").context(
        "SSH_AUTH_SOCK is not set — vs-connect needs an ssh session with agent forwarding \
         pointed at the vs-connect daemon (see README)",
    )?;
    let hostname = hostname();
    let mut stream = UnixStream::connect(&sock).with_context(|| {
        format!("connecting to {sock} — is the vs-connect daemon running on your local machine?")
    })?;
    // An editor can stay open for hours: wait mode must not time out.
    let read_timeout = if opts.wait {
        None
    } else {
        Some(Duration::from_secs(10))
    };
    stream.set_read_timeout(read_timeout)?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let mut requests: Vec<(Action, String)> = Vec::new();
    if let Some((l, r)) = &opts.diff {
        let left = diff_target(l)?;
        let right = diff_target(r)?;
        let msg = format!("diffing {left} and {right}");
        requests.push((Action::Diff { left, right }, msg));
    } else {
        for p in &opts.paths {
            let (kind, path, line, col) = classify_target(p, opts.force_goto);
            let msg = match (line, col) {
                (0, _) => format!("opening {path}"),
                (l, 0) => format!("opening {path} at line {l}"),
                (l, c) => format!("opening {path} at {l}:{c}"),
            };
            requests.push((Action::Open { kind, path, line, col }, msg));
        }
    }

    let user = std::env::var("USER").unwrap_or_default();
    let ssh_connection = std::env::var("SSH_CONNECTION").unwrap_or_default();
    for (action, msg) in requests {
        let req = OpenRequest {
            action,
            window: opts.window,
            wait: opts.wait,
            hostname: hostname.clone(),
            user: user.clone(),
            ssh_connection: ssh_connection.clone(),
        };
        write_frame(&mut stream, &extension(EXT_OPEN, &req.encode()))?;
        match read_reply(&mut stream)? {
            Reply::Success(authority) if opts.wait => {
                // Ack received: the editor is open and the daemon is holding
                // our reply until it closes. Status goes to stderr so tools
                // capturing stdout (EDITOR consumers) see nothing extra.
                eprintln!(
                    "{msg} in VS Code on your local machine{}; waiting until closed...",
                    describe_authority(&authority)
                );
                match read_reply(&mut stream).context("waiting for the editor to close")? {
                    Reply::Success(_) => eprintln!("editor closed"),
                    Reply::ExtensionFailure(reason) => bail!("{reason}"),
                    Reply::Failure => bail!("unexpected agent failure while waiting"),
                }
            }
            Reply::Success(authority) => println!(
                "{msg} in VS Code on your local machine{}",
                describe_authority(&authority)
            ),
            Reply::ExtensionFailure(reason) => bail!("daemon error: {reason}"),
            Reply::Failure => bail!(
                "the agent behind SSH_AUTH_SOCK is not the vs-connect daemon — this looks like \
                 plain agent forwarding. Point ForwardAgent at the vs-connect socket in your \
                 local ssh config (see README)."
            ),
        }
    }
    Ok(())
}

enum Reply {
    /// Success, with the resolved authority and its source when the daemon
    /// sent them (0.4.1+).
    Success(Option<(String, String)>),
    ExtensionFailure(String),
    Failure,
}

/// " (test-host)" normally; when the daemon had to fall back from argv parsing,
/// name the source so a wrong authority is diagnosable from the prompt.
fn describe_authority(authority: &Option<(String, String)>) -> String {
    match authority {
        Some((alias, how)) if how == "ssh argv" => format!(" ({alias})"),
        Some((alias, how)) => format!(" ({alias} — resolved via {how})"),
        None => String::new(),
    }
}

fn read_reply(stream: &mut UnixStream) -> Result<Reply> {
    let reply = read_frame(stream).context("waiting for daemon reply")?;
    match reply.first() {
        Some(&SSH_AGENT_SUCCESS) => {
            let mut c = Cursor::new(&reply[1..]);
            let authority = match (c.str(), c.str()) {
                (Ok(alias), Ok(how)) => Some((alias, how)),
                _ => None, // plain [6] from an older daemon or a wait-final
            };
            Ok(Reply::Success(authority))
        }
        Some(&SSH_AGENT_EXTENSION_FAILURE) => Ok(Reply::ExtensionFailure(
            Cursor::new(&reply[1..])
                .str()
                .unwrap_or_else(|_| "unknown error".into()),
        )),
        Some(&SSH_AGENT_FAILURE) => Ok(Reply::Failure),
        _ => anyhow::bail!("unexpected reply from agent socket"),
    }
}

/// Diff sides must be existing files — a missing path would only surface as
/// an error dialog in a freshly opened window, so fail here instead.
fn diff_target(p: &str) -> Result<String> {
    let abs = absolutize(Path::new(p));
    match std::fs::metadata(&abs) {
        Ok(m) if m.is_dir() => bail!("--diff compares files, and {} is a directory", abs.display()),
        Ok(_) => Ok(abs.to_string_lossy().into_owned()),
        Err(_) => bail!("diff target {} does not exist", abs.display()),
    }
}

/// Turn a shim argument into (kind, absolute path, line, col).
///
/// Goto is the default: `foo.rs:10:5` jumps to 10:5. A file whose literal
/// name contains the colons (rare, but possible) wins over the goto parse
/// unless -g forces it — mirroring how VS Code treats -g, with existence as
/// the tiebreak.
fn classify_target(raw: &str, force_goto: bool) -> (Kind, String, u32, u32) {
    let literal = absolutize(Path::new(raw));
    let literal_meta = std::fs::metadata(&literal).ok();

    if !force_goto {
        if let Some(m) = &literal_meta {
            let kind = if m.is_dir() { Kind::Folder } else { Kind::File };
            return (kind, literal.to_string_lossy().into_owned(), 0, 0);
        }
    }

    if let Some((base, line, col)) = split_goto_suffix(raw) {
        let base_abs = absolutize(Path::new(base));
        match std::fs::metadata(&base_abs) {
            // Positions are meaningless on a folder ("backup:2024" etc.)
            Ok(m) if m.is_dir() => {
                return (Kind::Folder, base_abs.to_string_lossy().into_owned(), 0, 0);
            }
            Ok(_) => return (Kind::File, base_abs.to_string_lossy().into_owned(), line, col),
            Err(_) => {
                if literal_meta.is_none() {
                    eprintln!(
                        "note: {} does not exist; opening as a new file",
                        base_abs.display()
                    );
                    return (Kind::File, base_abs.to_string_lossy().into_owned(), line, col);
                }
                // -g was forced but only the literal name exists — use it.
            }
        }
    }

    match literal_meta {
        Some(m) if m.is_dir() => (Kind::Folder, literal.to_string_lossy().into_owned(), 0, 0),
        Some(_) => (Kind::File, literal.to_string_lossy().into_owned(), 0, 0),
        None => {
            eprintln!("note: {} does not exist; opening as a file", literal.display());
            (Kind::File, literal.to_string_lossy().into_owned(), 0, 0)
        }
    }
}

/// Some((base, line, col)) when `raw` ends in :line or :line:col with
/// numeric parts. col is 0 when absent.
fn split_goto_suffix(raw: &str) -> Option<(&str, u32, u32)> {
    let (rest, last) = raw.rsplit_once(':')?;
    let last_num: u32 = last.parse().ok()?;
    if let Some((base, mid)) = rest.rsplit_once(':') {
        if let Ok(line) = mid.parse::<u32>() {
            if !base.is_empty() {
                return Some((base, line, last_num)); // base:line:col
            }
        }
    }
    if rest.is_empty() {
        None
    } else {
        Some((rest, last_num, 0)) // base:line
    }
}

/// Absolute + lexically cleaned (., ..), symlinks left alone so the window
/// opens on the path the user typed rather than its resolution.
fn absolutize(p: &Path) -> PathBuf {
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(p)
    };
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return "unknown".into();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Some(cli) when we're inside a VS Code terminal session whose own remote
/// CLI should handle the request.
fn vscode_terminal_cli() -> Option<PathBuf> {
    std::env::var("VSCODE_IPC_HOOK_CLI")
        .ok()
        .filter(|s| !s.is_empty())?;
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let mut candidates: Vec<PathBuf> = Vec::new();
    for (server_dir, cli_name) in [
        (".vscode-server", "code"),
        (".vscode-server-insiders", "code-insiders"),
    ] {
        let base = home.join(server_dir);
        // Newer layout: cli/servers/<commit>/server/bin/remote-cli/<code>
        collect_children(&base.join("cli/servers"), &mut candidates, |d| {
            d.join("server/bin/remote-cli").join(cli_name)
        });
        // Older layout: bin/<commit>/bin/remote-cli/<code>
        collect_children(&base.join("bin"), &mut candidates, |d| {
            d.join("bin/remote-cli").join(cli_name)
        });
    }
    // Several server versions may coexist; the newest is the live one.
    candidates
        .into_iter()
        .max_by_key(|p| p.metadata().and_then(|m| m.modified()).ok())
}

fn collect_children(base: &Path, out: &mut Vec<PathBuf>, make: impl Fn(&Path) -> PathBuf) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let candidate = make(&entry.path());
        if candidate.is_file() {
            out.push(candidate);
        }
    }
}

fn exec_real_cli(cli: &Path, args: &[String]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(cli).args(args).exec();
    bail!("failed to exec {}: {err}", cli.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolutize_cleans_dots() {
        assert_eq!(
            absolutize(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
    }

    #[test]
    fn absolutize_keeps_absolute() {
        assert_eq!(absolutize(Path::new("/x/y")), PathBuf::from("/x/y"));
    }

    #[test]
    fn absolutize_joins_cwd() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(absolutize(Path::new("sub/file")), cwd.join("sub/file"));
    }

    #[test]
    fn goto_suffix_line_only() {
        assert_eq!(split_goto_suffix("a/b.rs:10"), Some(("a/b.rs", 10, 0)));
    }

    #[test]
    fn goto_suffix_line_and_col() {
        assert_eq!(split_goto_suffix("a/b.rs:10:5"), Some(("a/b.rs", 10, 5)));
    }

    #[test]
    fn goto_suffix_absent() {
        assert_eq!(split_goto_suffix("a/b.rs"), None);
        assert_eq!(split_goto_suffix("a/b.rs:x"), None);
        assert_eq!(split_goto_suffix(":10"), None);
    }

    #[test]
    fn goto_suffix_nonnumeric_middle_falls_back_to_line() {
        // "v1.2:30" — only the trailing :30 is positional.
        assert_eq!(split_goto_suffix("v1.2:30"), Some(("v1.2", 30, 0)));
    }

    #[test]
    fn shim_args_flags() {
        let opts = parse_shim_args(
            ["-n", "-g", "src/x.rs:3"].iter().map(|s| s.to_string()).collect(),
        )
        .unwrap();
        assert_eq!(opts.window, WindowMode::New);
        assert!(opts.force_goto);
        assert_eq!(opts.paths, vec!["src/x.rs:3"]);
    }

    #[test]
    fn shim_args_diff() {
        let opts =
            parse_shim_args(["--diff", "a", "b"].iter().map(|s| s.to_string()).collect()).unwrap();
        assert_eq!(opts.diff, Some(("a".into(), "b".into())));
        assert!(opts.paths.is_empty());
    }

    #[test]
    fn shim_args_diff_wrong_arity() {
        assert!(parse_shim_args(["-d", "a"].iter().map(|s| s.to_string()).collect()).is_err());
    }

    #[test]
    fn shim_args_unknown_flag() {
        assert!(
            parse_shim_args(["--install-extension", "x"].iter().map(|s| s.to_string()).collect())
                .is_err()
        );
    }

    #[test]
    fn shim_args_wait() {
        let opts =
            parse_shim_args(["-w", "notes.md"].iter().map(|s| s.to_string()).collect()).unwrap();
        assert!(opts.wait);
        assert_eq!(opts.paths, vec!["notes.md"]);
    }

    #[test]
    fn wait_rejects_multiple_paths() {
        let opts =
            parse_shim_args(["-w", "a", "b"].iter().map(|s| s.to_string()).collect()).unwrap();
        let err = send_plan(opts).unwrap_err();
        assert!(err.to_string().contains("--wait supports exactly one path"));
    }

    #[test]
    fn classify_existing_file_with_colon_suffix_takes_position() {
        // The repo's own Cargo.toml exists; Cargo.toml:7 does not.
        let cwd = std::env::current_dir().unwrap();
        let (kind, path, line, col) = classify_target("Cargo.toml:7", false);
        assert_eq!(kind, Kind::File);
        assert_eq!(path, cwd.join("Cargo.toml").to_string_lossy());
        assert_eq!((line, col), (7, 0));
    }

    #[test]
    fn classify_existing_dir_wins_over_goto() {
        let (kind, _, line, _) = classify_target("src", false);
        assert_eq!(kind, Kind::Folder);
        assert_eq!(line, 0);
    }
}
