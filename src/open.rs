//! The remote side: send open requests down $SSH_AUTH_SOCK, which ssh has
//! forwarded back to the vs-connect daemon on the local machine.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::proto::*;

pub fn run(paths: Vec<String>) -> Result<()> {
    if let Some(cli) = vscode_terminal_cli() {
        return exec_real_cli(&cli, &paths);
    }
    send_open(paths)
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
        let (flags, paths): (Vec<String>, Vec<String>) =
            args.into_iter().partition(|a| a.starts_with('-'));
        if !flags.is_empty() {
            bail!(
                "unsupported flag(s) {}: over vs-connect this `code` shim only accepts file/folder paths",
                flags.join(" ")
            );
        }
        if paths.is_empty() {
            bail!("usage: code <path>...");
        }
        return send_open(paths);
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

fn send_open(paths: Vec<String>) -> Result<()> {
    let sock = std::env::var("SSH_AUTH_SOCK").context(
        "SSH_AUTH_SOCK is not set — vs-connect needs an ssh session with agent forwarding \
         pointed at the vs-connect daemon (see README)",
    )?;
    let hostname = hostname();
    let mut stream = UnixStream::connect(&sock).with_context(|| {
        format!("connecting to {sock} — is the vs-connect daemon running on your local machine?")
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    for p in &paths {
        let (kind, abs) = classify(p);
        let req = OpenRequest {
            kind,
            path: abs.clone(),
            hostname: hostname.clone(),
        };
        write_frame(&mut stream, &extension(EXT_OPEN, &req.encode()))?;
        let reply = read_frame(&mut stream).context("waiting for daemon reply")?;
        match reply.first() {
            Some(&SSH_AGENT_SUCCESS) => {
                println!("opening {abs} in VS Code on your local machine");
            }
            Some(&SSH_AGENT_EXTENSION_FAILURE) => {
                let reason = Cursor::new(&reply[1..])
                    .str()
                    .unwrap_or_else(|_| "unknown error".into());
                bail!("daemon error: {reason}");
            }
            Some(&SSH_AGENT_FAILURE) => bail!(
                "the agent behind SSH_AUTH_SOCK is not the vs-connect daemon — this looks like \
                 plain agent forwarding. Point ForwardAgent at the vs-connect socket in your \
                 local ssh config (see README)."
            ),
            _ => bail!("unexpected reply from agent socket"),
        }
    }
    Ok(())
}

fn classify(p: &str) -> (Kind, String) {
    let abs = absolutize(Path::new(p));
    let kind = match std::fs::metadata(&abs) {
        Ok(m) if m.is_dir() => Kind::Folder,
        Ok(_) => Kind::File,
        Err(_) => {
            eprintln!("note: {} does not exist; opening as a file", abs.display());
            Kind::File
        }
    };
    (kind, abs.to_string_lossy().into_owned())
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
}
