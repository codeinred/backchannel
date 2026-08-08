//! `backchannel status`: one command that makes sense on either machine —
//! reports the local daemon (if any) and what this shell's SSH_AUTH_SOCK
//! actually reaches.

use std::path::Path;

use anyhow::Result;

use crate::{daemon, paths};

pub fn run() -> Result<()> {
    println!("backchannel {}", env!("CARGO_PKG_VERSION"));

    let sock = paths::socket_path();
    println!("\nlocal daemon:");
    if sock.exists() {
        match daemon::ping(&sock) {
            Ok(Some(r)) => {
                println!("  running: pid {} (v{})", r.pid, r.version);
                println!("  socket:  {}", sock.display());
                println!("  agent passthrough: {}", r.upstream);
                println!("  log:     {}", paths::log_path().display());
            }
            _ => println!(
                "  socket {} exists but nothing answered (stale) — `backchannel daemon` will clean it up",
                sock.display()
            ),
        }
    } else {
        println!("  not running (no socket at {})", sock.display());
    }

    println!("\nthis shell:");
    match std::env::var("SSH_AUTH_SOCK") {
        Err(_) => println!("  SSH_AUTH_SOCK is not set"),
        Ok(s) => match daemon::ping(Path::new(&s)) {
            Ok(Some(r)) => println!(
                "  SSH_AUTH_SOCK reaches a backchannel daemon (pid {}) — `code <path>` will open \
                 windows on that machine",
                r.pid
            ),
            Ok(None) => println!(
                "  SSH_AUTH_SOCK reaches an ssh-agent that is not backchannel (normal on your \
                 local machine; on a remote it means plain agent forwarding)"
            ),
            Err(e) => println!("  SSH_AUTH_SOCK is set but unreachable: {e}"),
        },
    }
    if std::env::var("VSCODE_IPC_HOOK_CLI").is_ok_and(|s| !s.is_empty()) {
        println!("  VSCODE_IPC_HOOK_CLI is set — `code` defers to VS Code's own CLI here");
    }
    Ok(())
}
