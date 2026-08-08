//! Build vscode-remote:// URIs and hand them to the local VS Code CLI.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use crate::logging;
use crate::proto::Kind;

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

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

pub fn find_code() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("VS_CONNECT_CODE") {
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

pub fn open_uri(kind: Kind, uri: &str) -> Result<()> {
    let code = find_code().context(
        "could not find the `code` CLI — install VS Code's shell command or set VS_CONNECT_CODE",
    )?;
    let flag = match kind {
        Kind::Folder => "--folder-uri",
        Kind::File => "--file-uri",
    };
    let child = Command::new(&code)
        .arg(flag)
        .arg(uri)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", code.display()))?;

    // `code` exits almost immediately after handing the URI to the running
    // app; reap it off-thread so we can reply to the remote without waiting,
    // while still logging launcher failures.
    std::thread::spawn(move || match child.wait_with_output() {
        Ok(out) if !out.status.success() => logging::warn(format!(
            "code exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(e) => logging::warn(format!("waiting on code: {e}")),
        _ => {}
    });
    Ok(())
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
}
