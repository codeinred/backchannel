use std::path::PathBuf;

/// All state lives in one directory so the whole tool can be pointed
/// elsewhere (e.g. for tests) with a single env var.
pub fn base_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("VS_CONNECT_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var_os("HOME").expect("HOME is not set");
    PathBuf::from(home).join(".vs-connect")
}

pub fn socket_path() -> PathBuf {
    base_dir().join("agent.sock")
}

pub fn log_path() -> PathBuf {
    base_dir().join("daemon.log")
}

/// Optional fallback map for hosts whose ssh alias can't be recovered from
/// the connecting ssh process. Lines of `<hostname> <alias>`, `#` comments.
pub fn aliases_path() -> PathBuf {
    base_dir().join("aliases")
}
