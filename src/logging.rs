use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

struct Logger {
    file: Mutex<File>,
    echo: bool,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

pub fn init(path: &Path, echo: bool) -> std::io::Result<()> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let _ = LOGGER.set(Logger {
        file: Mutex::new(file),
        echo,
    });
    Ok(())
}

fn log(level: &str, msg: &str) {
    let ts = humantime::format_rfc3339_seconds(SystemTime::now());
    let line = format!("{ts} [{level}] {msg}\n");
    match LOGGER.get() {
        Some(l) => {
            if let Ok(mut f) = l.file.lock() {
                let _ = f.write_all(line.as_bytes());
            }
            if l.echo {
                eprint!("{line}");
            }
        }
        // Before init (or in client subcommands) fall back to stderr.
        None => eprint!("{line}"),
    }
}

pub fn info<S: AsRef<str>>(msg: S) {
    log("info", msg.as_ref());
}

pub fn warn<S: AsRef<str>>(msg: S) {
    log("warn", msg.as_ref());
}

pub fn error<S: AsRef<str>>(msg: S) {
    log("error", msg.as_ref());
}
