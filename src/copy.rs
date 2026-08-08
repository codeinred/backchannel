//! `back copy [FILE]`: put a file (or stdin) on the clipboard. From a
//! remote ssh session that means *your local machine's* clipboard, via the
//! daemon; on a desktop it sets the local clipboard directly, so the same
//! command works everywhere.

use std::io::Read as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::open::{Reply, channel_is_backchannel, hostname, in_ssh_session, read_reply};
use crate::proto::*;
use crate::clipboard;

pub fn run(file: Option<String>) -> Result<()> {
    let data = match &file {
        Some(p) => std::fs::read(p).with_context(|| format!("reading {p}"))?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading stdin")?;
            buf
        }
    };
    if data.is_empty() {
        bail!("nothing to copy");
    }
    if data.len() > clipboard::MAX_COPY_BYTES {
        bail!(
            "{} bytes exceeds the {} MiB copy limit",
            data.len(),
            clipboard::MAX_COPY_BYTES / (1024 * 1024)
        );
    }
    let kind = clipboard::detect_kind(&data).context(
        "content is neither UTF-8 text nor a recognized image (png/jpeg/gif/tiff)",
    )?;

    if channel_is_backchannel() {
        return send_copy(kind, data);
    }
    if in_ssh_session() {
        bail!(
            "no backchannel in this ssh session — is the daemon running on your local machine, \
             and was this session opened after it started? `back status` has details."
        );
    }
    // In person at this machine: the local clipboard is the local clipboard.
    clipboard::set(kind, &data)?;
    eprintln!("copied {} bytes ({kind}) to the clipboard", data.len());
    Ok(())
}

fn send_copy(kind: &'static str, data: Vec<u8>) -> Result<()> {
    let sock = std::env::var("SSH_AUTH_SOCK").context("SSH_AUTH_SOCK is not set")?;
    let mut stream = UnixStream::connect(Path::new(&sock)).with_context(|| {
        format!("connecting to {sock} — is the backchannel daemon running on your local machine?")
    })?;
    // Big payloads over slow links need patience.
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;

    let len = data.len();
    let req = CopyRequest {
        kind: kind.to_string(),
        hostname: hostname(),
        data,
    };
    let stats = crate::progress::write_frame_with_progress(
        &mut stream,
        &extension(EXT_COPY, &req.encode()),
        "clipboard",
    )?;
    match read_reply(&mut stream)? {
        Reply::Success(_) => {
            match stats.summary() {
                Some(summary) => eprintln!(
                    "copied {kind} to the clipboard on your local machine ({summary})"
                ),
                None => eprintln!(
                    "copied {len} bytes ({kind}) to the clipboard on your local machine"
                ),
            }
            Ok(())
        }
        Reply::ExtensionFailure(reason) => bail!("daemon error: {reason}"),
        Reply::Failure => bail!(
            "the agent behind SSH_AUTH_SOCK is not the backchannel daemon — this looks like \
             plain agent forwarding. Point ForwardAgent at the backchannel socket in your \
             local ssh config (see README)."
        ),
    }
}
