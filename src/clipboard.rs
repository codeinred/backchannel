//! Set the local clipboard. No heavy dependencies: text and images go
//! through the tools every desktop already has (pbcopy/osascript on macOS,
//! wl-copy/xclip on Linux).

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// Client-side payload cap (copy and open-file transfers); MAX_FRAME
/// (256 MiB) leaves headroom above this.
pub const MAX_COPY_BYTES: usize = 200 * 1024 * 1024;

/// Sniff content: known image magics first, then UTF-8 text. None means
/// "refuse rather than corrupt someone's clipboard".
pub fn detect_kind(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(&[0x89, b'P', b'N', b'G']) {
        return Some("image/png");
    }
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if data.starts_with(b"II*\x00") || data.starts_with(b"MM\x00*") {
        return Some("image/tiff");
    }
    if std::str::from_utf8(data).is_ok() {
        return Some("text");
    }
    None
}

pub fn set(kind: &str, data: &[u8]) -> Result<()> {
    if let Some(cmd) = std::env::var_os("BACKCHANNEL_CLIPBOARD") {
        // Override hook (used by tests): invoked as `<cmd> <kind>` with the
        // data on stdin.
        return pipe_to(&PathBuf::from(cmd), &[kind.to_string()], data, &[]);
    }
    if kind == "text" {
        set_text(data)
    } else {
        set_image(kind, data)
    }
}

fn pipe_to(program: &PathBuf, args: &[String], data: &[u8], envs: &[(&str, &str)]) -> Result<()> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning {}", program.display()))?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(data)
        .with_context(|| format!("writing to {}", program.display()))?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "{} exited with {}: {}",
            program.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_text(data: &[u8]) -> Result<()> {
    // pbcopy interprets input per locale; daemons often have none set, which
    // mangles UTF-8 without this.
    pipe_to(
        &PathBuf::from("/usr/bin/pbcopy"),
        &[],
        data,
        &[("LC_CTYPE", "UTF-8")],
    )
}

#[cfg(target_os = "macos")]
fn set_image(kind: &str, data: &[u8]) -> Result<()> {
    let class = match kind {
        "image/png" => "PNGf",
        "image/jpeg" => "JPEG",
        "image/gif" => "GIFf",
        "image/tiff" => "TIFF",
        other => bail!("unsupported image kind {other:?}"),
    };
    // pbcopy is text-only; images go through AppleScript, which needs a file.
    // The temp filename is generated (no quoting hazards in the script).
    let tmp = std::env::temp_dir().join(format!(
        "backchannel-clip-{}-{}",
        std::process::id(),
        data.len()
    ));
    std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
    let script = format!(
        r#"set the clipboard to (read (POSIX file "{}") as «class {class}»)"#,
        tmp.display()
    );
    let out = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(&script)
        .output();
    let _ = std::fs::remove_file(&tmp);
    let out = out.context("running osascript")?;
    if !out.status.success() {
        bail!(
            "osascript failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_text(data: &[u8]) -> Result<()> {
    linux_clip(None, data)
}

#[cfg(target_os = "linux")]
fn set_image(kind: &str, data: &[u8]) -> Result<()> {
    linux_clip(Some(kind), data)
}

#[cfg(target_os = "linux")]
fn linux_clip(mime: Option<&str>, data: &[u8]) -> Result<()> {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|s| !s.is_empty());
    if wayland {
        if let Some(wl) = crate::launch::which("wl-copy") {
            let mut args: Vec<String> = Vec::new();
            if let Some(m) = mime {
                args.push("-t".into());
                args.push(m.into());
            }
            return pipe_to(&wl, &args, data, &[]);
        }
    }
    if let Some(xclip) = crate::launch::which("xclip") {
        let mut args: Vec<String> = vec!["-selection".into(), "clipboard".into(), "-i".into()];
        if let Some(m) = mime {
            args.push("-t".into());
            args.push(m.into());
        }
        return pipe_to(&xclip, &args, data, &[]);
    }
    bail!("no clipboard tool found — install wl-clipboard (wayland) or xclip (x11)");
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn set_text(_data: &[u8]) -> Result<()> {
    bail!("clipboard not implemented on this platform");
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn set_image(_kind: &str, _data: &[u8]) -> Result<()> {
    bail!("clipboard not implemented on this platform");
}

#[cfg(test)]
mod tests {
    use super::detect_kind;

    #[test]
    fn detects_kinds() {
        assert_eq!(detect_kind(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(detect_kind(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(detect_kind(b"GIF89a..."), Some("image/gif"));
        assert_eq!(detect_kind(b"II*\x00tiff"), Some("image/tiff"));
        assert_eq!(detect_kind(b"MM\x00*tiff"), Some("image/tiff"));
        assert_eq!(detect_kind("plain text, with unicode: héllo".as_bytes()), Some("text"));
        assert_eq!(detect_kind(&[0x00, 0xFF, 0xFE, 0x01]), None);
    }
}
