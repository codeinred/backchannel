//! The local daemon. ssh forwards our socket to remotes as "the agent", so
//! every connection here is either real agent traffic (relayed verbatim to
//! the actual ssh-agent) or a vs-connect extension message (ping / open /
//! shutdown) from the remote wrapper or another vs-connect process.

use std::ffi::CString;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::proto::*;
use crate::{launch, logging, paths, peer, ssh_argv};

const IO_TIMEOUT: Duration = Duration::from_secs(10);

enum Existing {
    None,
    Stale,
    Alive(u32),
}

pub fn run(replace: bool, foreground: bool) -> Result<()> {
    let dir = paths::base_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    // The directory is the access control; sockets get sloppy modes on some
    // platforms, so keep the whole dir owner-only.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    logging::init(&paths::log_path(), foreground)
        .with_context(|| format!("opening log {}", paths::log_path().display()))?;

    let sock_path = paths::socket_path();
    match probe_existing(&sock_path) {
        // Quiet: shell rcs run this on every new terminal, so the expected
        // outcomes (started / already running) print nothing; only errors
        // reach stderr. `vs-connect status` is the interactive view.
        Existing::Alive(_) if !replace => return Ok(()),
        Existing::Alive(pid) => {
            logging::info(format!("replacing running daemon (pid {pid})"));
            shutdown_existing(&sock_path)?;
        }
        Existing::Stale => {
            logging::info("removing stale agent socket");
            let _ = std::fs::remove_file(&sock_path);
        }
        Existing::None => {}
    }

    let upstream = resolve_upstream(&sock_path);
    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("binding {}", sock_path.display()))?;
    let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));

    if !foreground {
        daemonize()?;
    }
    install_signal_cleanup(&sock_path);

    let my_uid = unsafe { libc::geteuid() } as u32;
    let upstream_desc = upstream
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "none".into());
    logging::info(format!(
        "daemon started (pid {}, version {}, socket {}, upstream agent: {})",
        std::process::id(),
        env!("CARGO_PKG_VERSION"),
        sock_path.display(),
        upstream_desc
    ));

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let upstream = upstream.clone();
                let upstream_desc = upstream_desc.clone();
                let sock_path = sock_path.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_client(stream, upstream, &upstream_desc, my_uid, &sock_path)
                    {
                        logging::warn(format!("client connection error: {e:#}"));
                    }
                });
            }
            Err(e) => logging::warn(format!("accept failed: {e}")),
        }
    }
    Ok(())
}

/// Ping whatever is listening on `path`. Ok(Some) = a vs-connect daemon,
/// Ok(None) = something answered but it isn't us (a real agent), Err = no
/// listener / no answer. Shared with `status`.
pub fn ping(path: &Path) -> io::Result<Option<PingReply>> {
    let mut s = UnixStream::connect(path)?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    s.set_write_timeout(Some(Duration::from_secs(2)))?;
    write_frame(&mut s, &extension(EXT_PING, &[]))?;
    let frame = read_frame(&mut s)?;
    Ok(PingReply::decode(&frame))
}

fn probe_existing(path: &Path) -> Existing {
    if !path.exists() {
        return Existing::None;
    }
    match ping(path) {
        Ok(Some(reply)) => Existing::Alive(reply.pid),
        // A live non-vs-connect agent on our socket path would be bizarre;
        // treat like stale — we own this path.
        _ => Existing::Stale,
    }
}

fn shutdown_existing(path: &Path) -> Result<()> {
    let mut s = UnixStream::connect(path).context("connecting to daemon to replace it")?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    s.set_write_timeout(Some(Duration::from_secs(2)))?;
    write_frame(&mut s, &extension(EXT_SHUTDOWN, &[]))?;
    let _ = read_frame(&mut s); // best-effort ack
    // Wait for the old daemon to unlink its socket so our bind can't race it.
    for _ in 0..40 {
        if !path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}

/// The real agent we proxy ordinary requests to: whatever SSH_AUTH_SOCK
/// pointed at when the daemon started — guarding against being pointed at
/// ourselves, which would be an infinite proxy loop.
fn resolve_upstream(our_sock: &Path) -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os("SSH_AUTH_SOCK")?);
    let same_path = p == *our_sock
        || match (p.canonicalize(), our_sock.canonicalize()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
    if same_path {
        logging::warn(
            "SSH_AUTH_SOCK points at vs-connect's own socket; agent passthrough disabled to avoid a proxy loop",
        );
        return None;
    }
    Some(p)
}

fn daemonize() -> Result<()> {
    unsafe {
        match libc::fork() {
            -1 => bail!("fork failed: {}", io::Error::last_os_error()),
            0 => {}
            _child => libc::_exit(0),
        }
        libc::setsid();
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
    Ok(())
}

static CLEANUP_PATH: OnceLock<CString> = OnceLock::new();

extern "C" fn on_term(_sig: libc::c_int) {
    // Only async-signal-safe calls here.
    if let Some(p) = CLEANUP_PATH.get() {
        unsafe {
            libc::unlink(p.as_ptr());
        }
    }
    unsafe { libc::_exit(0) }
}

fn install_signal_cleanup(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c) = CString::new(path.as_os_str().as_bytes()) {
        let _ = CLEANUP_PATH.set(c);
    }
    let handler = on_term as extern "C" fn(libc::c_int) as usize;
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

fn handle_client(
    mut stream: UnixStream,
    upstream: Option<PathBuf>,
    upstream_desc: &str,
    my_uid: u32,
    sock_path: &Path,
) -> Result<()> {
    let peer = peer::peer_info(&stream).ok();
    if let Some(p) = peer {
        if p.uid != my_uid {
            logging::warn(format!(
                "rejecting connection from uid {} (pid {})",
                p.uid, p.pid
            ));
            return Ok(());
        }
    }

    // One upstream connection per client connection mirrors the client's
    // lifetime and keeps any agent-side per-connection state coherent.
    let mut proxy_conn: Option<UnixStream> = None;

    loop {
        let msg = match read_frame(&mut stream) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        match parse_extension(&msg) {
            Some((name, _)) if name == EXT_PING => {
                let reply = PingReply {
                    version: env!("CARGO_PKG_VERSION").into(),
                    pid: std::process::id(),
                    upstream: upstream_desc.to_string(),
                };
                write_frame(&mut stream, &reply.encode())?;
            }
            Some((name, _)) if name == EXT_SHUTDOWN => {
                logging::info(format!(
                    "shutdown requested by pid {}",
                    peer.map(|p| p.pid.to_string()).unwrap_or_else(|| "?".into())
                ));
                let _ = write_frame(&mut stream, &success_frame());
                let _ = std::fs::remove_file(sock_path);
                std::process::exit(0);
            }
            Some((name, data)) if name == EXT_OPEN => {
                let reply = match handle_open(data, peer) {
                    Ok(()) => success_frame(),
                    Err(e) => {
                        logging::error(format!("open failed: {e:#}"));
                        extension_failure(&format!("{e:#}"))
                    }
                };
                write_frame(&mut stream, &reply)?;
            }
            // Anything else — identities, signing, session-bind@openssh.com,
            // unknown extensions — is real agent traffic. Relay verbatim.
            _ => {
                let reply = proxy_roundtrip(&mut proxy_conn, upstream.as_deref(), &msg);
                write_frame(&mut stream, &reply)?;
            }
        }
    }
}

fn proxy_roundtrip(
    conn: &mut Option<UnixStream>,
    upstream: Option<&Path>,
    msg: &[u8],
) -> Vec<u8> {
    let Some(up) = upstream else {
        return failure_frame();
    };
    // Two attempts: a cached connection may have gone stale since the last
    // request; reconnect once before giving up.
    for attempt in 0..2 {
        if conn.is_none() {
            match UnixStream::connect(up) {
                Ok(s) => {
                    let _ = s.set_read_timeout(Some(IO_TIMEOUT));
                    let _ = s.set_write_timeout(Some(IO_TIMEOUT));
                    *conn = Some(s);
                }
                Err(e) => {
                    logging::warn(format!("cannot reach agent {}: {e}", up.display()));
                    return failure_frame();
                }
            }
        }
        let s = conn.as_mut().expect("connection just established");
        match write_frame(s, msg).and_then(|_| read_frame(s)) {
            Ok(reply) => return reply,
            Err(e) => {
                *conn = None;
                if attempt == 1 {
                    logging::warn(format!("agent passthrough failed: {e}"));
                    return failure_frame();
                }
            }
        }
    }
    unreachable!()
}

fn handle_open(data: &[u8], peer: Option<peer::PeerInfo>) -> Result<()> {
    let req = OpenRequest::decode(data).context("decoding open request")?;
    let (alias, how) = resolve_alias(peer, &req.hostname);
    let args = launch::code_args(&alias, &req.action, req.window);
    logging::info(format!(
        "{} from host '{}' (alias '{}' via {}) -> code {}",
        describe(&req.action),
        req.hostname,
        alias,
        how,
        args.join(" ")
    ));
    launch::run_code(args)
}

fn describe(action: &Action) -> String {
    match action {
        Action::Open { kind, path, line: 0, .. } => format!("open {} {}", kind.as_str(), path),
        Action::Open { kind, path, line, col: 0 } => {
            format!("open {} {}:{}", kind.as_str(), path, line)
        }
        Action::Open { kind, path, line, col } => {
            format!("open {} {}:{}:{}", kind.as_str(), path, line, col)
        }
        Action::Diff { left, right } => format!("diff {} <-> {}", left, right),
    }
}

/// Best source first: the argv of the ssh process that carried the request,
/// then the user's aliases file, then the hostname the remote reported.
fn resolve_alias(peer: Option<peer::PeerInfo>, hostname: &str) -> (String, &'static str) {
    if let Some(p) = peer {
        if let Some(argv) = peer::process_argv(p.pid) {
            if let Some(dest) = ssh_argv::destination(&argv) {
                return (dest, "ssh argv");
            }
        }
    }
    if let Some(alias) = alias_lookup(hostname) {
        return (alias, "aliases file");
    }
    (hostname.trim_end_matches('.').to_string(), "remote hostname")
}

fn alias_lookup(hostname: &str) -> Option<String> {
    let content = std::fs::read_to_string(paths::aliases_path()).ok()?;
    let short = hostname.split('.').next().unwrap_or(hostname);
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(host), Some(alias)) = (parts.next(), parts.next()) else {
            continue;
        };
        if host == hostname || host == short {
            return Some(alias.to_string());
        }
    }
    None
}
