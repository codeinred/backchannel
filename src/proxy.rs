//! `back proxy list|stop`: inspect and manage the daemon's ssh -L tunnel
//! children. Works from either end — over the channel from a remote, or
//! against the local daemon socket in person.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::open::channel_is_backchannel;
use crate::proto::*;
use crate::{daemon, paths};

/// The daemon to talk to: the forwarded channel when we're on a remote,
/// otherwise the local socket.
fn daemon_socket() -> Result<PathBuf> {
    if channel_is_backchannel() {
        return Ok(PathBuf::from(
            std::env::var_os("SSH_AUTH_SOCK").expect("checked by channel_is_backchannel"),
        ));
    }
    let local = paths::socket_path();
    if matches!(daemon::ping(&local), Ok(Some(_))) {
        return Ok(local);
    }
    bail!(
        "no backchannel daemon reachable (neither $SSH_AUTH_SOCK nor {})",
        local.display()
    );
}

pub fn query_tunnels(sock: &Path) -> Result<Option<Vec<TunnelEntry>>> {
    let mut s = UnixStream::connect(sock)
        .with_context(|| format!("connecting to {}", sock.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    write_frame(&mut s, &extension(EXT_TUNNELS, &[]))?;
    let frame = read_frame(&mut s)?;
    Ok(parse_tunnels_reply(&frame))
}

pub fn list() -> Result<()> {
    let sock = daemon_socket()?;
    match query_tunnels(&sock)? {
        None => bail!("the agent at {} did not answer as a backchannel daemon", sock.display()),
        Some(entries) if entries.is_empty() => println!("no active tunnels"),
        Some(entries) => {
            for e in entries {
                println!(
                    "localhost:{} -> {}:{} (ssh pid {})",
                    e.local_port, e.alias, e.remote_port, e.pid
                );
            }
        }
    }
    Ok(())
}

pub fn stop(port: Option<u16>, all: bool) -> Result<()> {
    if all == port.is_some() {
        bail!("specify a local port or --all");
    }
    let sock = daemon_socket()?;
    let mut s = UnixStream::connect(&sock)
        .with_context(|| format!("connecting to {}", sock.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut data = Vec::new();
    put_u32(&mut data, port.unwrap_or(0) as u32);
    write_frame(&mut s, &extension(EXT_PROXY_STOP, &data))?;
    let frame = read_frame(&mut s)?;
    match frame.first() {
        Some(&SSH_AGENT_SUCCESS) => {
            let msg = Cursor::new(&frame[1..])
                .str()
                .unwrap_or_else(|_| "stopped".into());
            println!("{msg}");
            Ok(())
        }
        Some(&SSH_AGENT_EXTENSION_FAILURE) => {
            let reason = Cursor::new(&frame[1..])
                .str()
                .unwrap_or_else(|_| "unknown error".into());
            bail!("{reason}");
        }
        _ => bail!("unexpected reply from agent socket"),
    }
}
