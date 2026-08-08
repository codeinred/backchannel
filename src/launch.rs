//! Build vscode-remote:// URIs and hand them to the local VS Code CLI.

use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use crate::logging;
use crate::proto::{Kind, WindowMode};

/// Encode everything except unreserved chars and '/', so paths with spaces
/// and unicode survive the URI trip.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub fn remote_uri(alias: &str, path: &str) -> String {
    format!(
        "vscode-remote://ssh-remote+{}{}",
        alias,
        utf8_percent_encode(path, PATH_SEGMENT)
    )
}

/// The argv for the local `code` CLI. Folders go through --folder-uri;
/// files ride --remote + --goto so positions work; diffs ride --remote +
/// --diff. Plain paths (not URIs) are fine with --remote because the shim
/// always sends absolute paths.
pub fn code_args(
    alias: &str,
    action: &crate::proto::Action,
    window: WindowMode,
    wait: bool,
) -> Vec<String> {
    use crate::proto::Action;
    let mut args: Vec<String> = Vec::new();
    if wait {
        args.push("--wait".into());
    }
    match window {
        WindowMode::New => args.push("--new-window".into()),
        WindowMode::Reuse => args.push("--reuse-window".into()),
        WindowMode::Default => {}
    }
    let authority = format!("ssh-remote+{alias}");
    match action {
        Action::Open { kind: Kind::Folder, path, .. } => {
            args.push("--folder-uri".into());
            args.push(remote_uri(alias, path));
        }
        Action::Open { kind: Kind::File, path, line, col } => {
            args.push("--remote".into());
            args.push(authority);
            args.push("--goto".into());
            let mut target = path.clone();
            if *line > 0 {
                target.push_str(&format!(":{line}"));
                if *col > 0 {
                    target.push_str(&format!(":{col}"));
                }
            }
            args.push(target);
        }
        Action::Diff { left, right } => {
            args.push("--remote".into());
            args.push(authority);
            args.push("--diff".into());
            args.push(left.clone());
            args.push(right.clone());
        }
        // URLs never reach the code CLI; the daemon routes them to open_url.
        Action::Url { .. } => unreachable!("URL actions are handled before code_args"),
    }
    args
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

pub fn find_code() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("BACKCHANNEL_CODE") {
        return Some(PathBuf::from(p));
    }
    if let Some(p) = which("code") {
        return Some(p);
    }
    // The daemon may run without the shell's full PATH (e.g. under launchd).
    let mut candidates = vec![
        PathBuf::from("/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"),
        PathBuf::from("/usr/local/bin/code"),
        PathBuf::from("/usr/bin/code"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        candidates.insert(
            1,
            PathBuf::from(home)
                .join("Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"),
        );
    }
    candidates.into_iter().find(|p| p.is_file())
}

pub fn run_code(args: Vec<String>) -> Result<()> {
    let code = find_code().context(
        "could not find the `code` CLI — install VS Code's shell command or set BACKCHANNEL_CODE",
    )?;
    spawn_and_reap(&code, &args)
}

/// Open a URL in the local default browser.
pub fn open_url(url: &str) -> Result<()> {
    let opener = find_opener().context(
        "no URL opener found — install xdg-open, or set BACKCHANNEL_OPENER to a command that \
         takes a URL argument",
    )?;
    spawn_and_reap(&opener, std::slice::from_ref(&url.to_string()))
}

fn find_opener() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("BACKCHANNEL_OPENER") {
        return Some(PathBuf::from(p));
    }
    #[cfg(target_os = "macos")]
    {
        let open = PathBuf::from("/usr/bin/open");
        if open.is_file() {
            return Some(open);
        }
    }
    which("xdg-open")
}

/// Launchers exit almost immediately after handing off to the running app;
/// reap off-thread so we can reply to the remote without waiting, while
/// still logging launcher failures.
fn spawn_and_reap(program: &PathBuf, args: &[String]) -> Result<()> {
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", program.display()))?;

    let name = program.display().to_string();
    std::thread::spawn(move || match child.wait_with_output() {
        Ok(out) if !out.status.success() => logging::warn(format!(
            "{name} exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(e) => logging::warn(format!("waiting on {name}: {e}")),
        _ => {}
    });
    Ok(())
}

/// A spawned `code --wait` CLI. Its stderr is drained off-thread — the pipe
/// must be consumed or a chatty child could block on it mid-wait.
pub struct WaitingCode {
    child: Child,
    stderr_rx: std::sync::mpsc::Receiver<String>,
}

pub fn spawn_code_waiting(args: &[String]) -> Result<WaitingCode> {
    let code = find_code().context(
        "could not find the `code` CLI — install VS Code's shell command or set BACKCHANNEL_CODE",
    )?;
    let mut child = Command::new(&code)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", code.display()))?;
    let (tx, rx) = std::sync::mpsc::channel();
    if let Some(mut stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            let _ = tx.send(s);
        });
    }
    Ok(WaitingCode {
        child,
        stderr_rx: rx,
    })
}

/// Block until the spawned CLI exits (the editor was closed) or the client
/// connection dies (remote Ctrl-C, dropped ssh session) — in which case the
/// CLI is killed so it doesn't wait forever. The editor window itself stays
/// open either way, matching native `code -w` behavior on interrupt.
///
/// Event-driven, no polling: a waiter thread turns child-exit into a byte
/// on a socketpair, and poll(2) sleeps on that alongside the client fd.
/// Client readiness is inspected with MSG_PEEK only — nothing is consumed,
/// so a frame a client sends mid-wait stays intact for the caller's frame
/// loop once the wait resolves.
pub fn wait_until_closed(wc: WaitingCode, client: &UnixStream) -> Result<()> {
    use std::os::fd::AsRawFd;

    let WaitingCode {
        mut child,
        stderr_rx,
    } = wc;
    let pid = child.id() as libc::pid_t;
    let (status_tx, status_rx) = std::sync::mpsc::channel();
    let (mut exit_w, exit_r) =
        UnixStream::pair().context("creating exit-notification socketpair")?;
    std::thread::spawn(move || {
        let status = child.wait();
        let _ = status_tx.send(status);
        let _ = std::io::Write::write_all(&mut exit_w, &[1]);
    });

    let mut disconnected = false;
    // Set to -1 (which poll ignores) once the client needs no more watching.
    let mut client_fd = client.as_raw_fd();
    loop {
        let mut fds = [
            libc::pollfd {
                fd: exit_r.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: client_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            unsafe { libc::kill(pid, libc::SIGTERM) };
            return Err(anyhow!("poll failed during --wait: {e}"));
        }

        if fds[0].revents != 0 {
            // Child exited (naturally, or from our SIGTERM after disconnect).
            let status = match status_rx.recv() {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(anyhow!("waiting on code: {e}")),
                Err(_) => return Err(anyhow!("child waiter thread vanished")),
            };
            return if disconnected {
                Err(anyhow!("remote client disconnected during --wait"))
            } else if status.success() {
                Ok(())
            } else {
                let stderr = stderr_rx
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap_or_default();
                Err(anyhow!("code exited with {status}: {}", stderr.trim()))
            };
        }

        if client_fd >= 0 && fds[1].revents != 0 {
            let mut probe = [0u8; 1];
            let n = unsafe {
                libc::recv(
                    client_fd,
                    probe.as_mut_ptr() as *mut libc::c_void,
                    1,
                    libc::MSG_PEEK,
                )
            };
            if n == 0 {
                // EOF: the client is gone. Stop the waiter CLI; its exit
                // arrives on the socketpair next iteration.
                unsafe { libc::kill(pid, libc::SIGTERM) };
                disconnected = true;
                client_fd = -1;
            } else if n > 0 {
                // A pipelined frame. Leave it queued (MSG_PEEK consumed
                // nothing) and stop watching readability so we don't spin.
                logging::warn("client sent data during --wait; queued until the wait resolves");
                client_fd = -1;
            } else {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    unsafe { libc::kill(pid, libc::SIGTERM) };
                    disconnected = true;
                    client_fd = -1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_encodes_spaces_but_not_slashes() {
        assert_eq!(
            remote_uri("test-host", "/opt/my pages/vtz"),
            "vscode-remote://ssh-remote+test-host/opt/my%20pages/vtz"
        );
    }

    #[test]
    fn uri_keeps_user_at_host() {
        assert_eq!(
            remote_uri("user@host", "/srv"),
            "vscode-remote://ssh-remote+user@host/srv"
        );
    }

    #[test]
    fn args_for_folder() {
        use crate::proto::Action;
        assert_eq!(
            code_args(
                "test-host",
                &Action::Open { kind: Kind::Folder, path: "/opt".into(), line: 0, col: 0 },
                WindowMode::New,
                false
            ),
            vec!["--new-window", "--folder-uri", "vscode-remote://ssh-remote+test-host/opt"]
        );
    }

    #[test]
    fn args_for_file_with_position() {
        use crate::proto::Action;
        assert_eq!(
            code_args(
                "test-host",
                &Action::Open { kind: Kind::File, path: "/a/b.rs".into(), line: 10, col: 5 },
                WindowMode::Default,
                true
            ),
            vec!["--wait", "--remote", "ssh-remote+test-host", "--goto", "/a/b.rs:10:5"]
        );
    }

    #[test]
    fn args_for_diff() {
        use crate::proto::Action;
        assert_eq!(
            code_args(
                "test-host",
                &Action::Diff { left: "/a".into(), right: "/b".into() },
                WindowMode::Reuse,
                false
            ),
            vec!["--reuse-window", "--remote", "ssh-remote+test-host", "--diff", "/a", "/b"]
        );
    }
}
