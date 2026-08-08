//! The local daemon. ssh forwards our socket to remotes as "the agent", so
//! every connection here is either real agent traffic (relayed verbatim to
//! the actual ssh-agent) or a backchannel extension message (ping / open /
//! shutdown) from the remote wrapper or another backchannel process.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::proto::*;
use crate::{launch, logging, paths, peer, ssh_argv};

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// ssh -L children keyed by local port. The registry is the ground truth
/// `back status` / `back proxy list` report from.
struct Tunnel {
    alias: String,
    remote_port: u16,
    child: Child,
}

static TUNNELS: OnceLock<Mutex<HashMap<u16, Tunnel>>> = OnceLock::new();

fn tunnels() -> &'static Mutex<HashMap<u16, Tunnel>> {
    TUNNELS.get_or_init(|| Mutex::new(HashMap::new()))
}

static DAEMONIZED: AtomicBool = AtomicBool::new(false);

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
        // reach stderr. `back status` is the interactive view.
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

/// Ping whatever is listening on `path`. Ok(Some) = a backchannel daemon,
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
        // A live non-backchannel agent on our socket path would be bizarre;
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
            "SSH_AUTH_SOCK points at backchannel's own socket; agent passthrough disabled to avoid a proxy loop",
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
        DAEMONIZED.store(true, Ordering::Relaxed);
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
    // Daemonized (post-setsid) we lead our own process group containing the
    // ssh -L tunnel children — take them down with us. Never in foreground
    // mode, where the group may include the spawning shell or test runner.
    if DAEMONIZED.load(Ordering::Relaxed) {
        unsafe {
            libc::kill(0, libc::SIGTERM);
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
                kill_all_tunnels();
                let _ = write_frame(&mut stream, &success_frame());
                let _ = std::fs::remove_file(sock_path);
                std::process::exit(0);
            }
            Some((name, _)) if name == EXT_TUNNELS => {
                let mut reg = tunnels().lock().unwrap();
                prune_dead(&mut reg);
                let entries: Vec<TunnelEntry> = reg
                    .iter()
                    .map(|(lp, t)| TunnelEntry {
                        alias: t.alias.clone(),
                        local_port: *lp,
                        remote_port: t.remote_port,
                        pid: t.child.id(),
                    })
                    .collect();
                drop(reg);
                write_frame(&mut stream, &tunnels_reply(&entries))?;
            }
            Some((name, data)) if name == EXT_PROXY_STOP => {
                let reply = handle_proxy_stop(data);
                write_frame(&mut stream, &reply)?;
            }
            Some((name, data)) if name == EXT_OPEN => {
                handle_open(data, peer, &mut stream)?;
            }
            Some((name, data)) if name == EXT_PULL => {
                handle_pull(data, peer, &mut stream)?;
            }
            Some((name, data)) if name == EXT_OPENFILE => {
                let reply = match handle_open_file(data) {
                    Ok(summary) => {
                        logging::info(summary);
                        success_frame()
                    }
                    Err(e) => {
                        logging::error(format!("open file failed: {e:#}"));
                        extension_failure(&format!("{e:#}"))
                    }
                };
                write_frame(&mut stream, &reply)?;
            }
            Some((name, data)) if name == EXT_COPY => {
                let reply = match handle_copy(data) {
                    Ok(summary) => {
                        logging::info(summary);
                        success_frame()
                    }
                    Err(e) => {
                        logging::error(format!("copy failed: {e:#}"));
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

fn prune_dead(reg: &mut HashMap<u16, Tunnel>) {
    reg.retain(|lp, t| match t.child.try_wait() {
        Ok(None) => true,
        _ => {
            logging::warn(format!(
                "tunnel localhost:{lp} -> {}:{} died; removing",
                t.alias, t.remote_port
            ));
            false
        }
    });
}

fn kill_tunnel(local_port: u16, t: &mut Tunnel) {
    logging::info(format!(
        "stopping tunnel localhost:{local_port} -> {}:{} (ssh pid {})",
        t.alias,
        t.remote_port,
        t.child.id()
    ));
    let _ = t.child.kill();
    let _ = t.child.wait();
}

fn kill_all_tunnels() {
    let mut reg = tunnels().lock().unwrap();
    for (lp, t) in reg.iter_mut() {
        kill_tunnel(*lp, t);
    }
    reg.clear();
}

fn handle_proxy_stop(data: &[u8]) -> Vec<u8> {
    let port = Cursor::new(data).u32().unwrap_or(0) as u16;
    let mut reg = tunnels().lock().unwrap();
    prune_dead(&mut reg);
    let summary = if port == 0 {
        let n = reg.len();
        for (lp, t) in reg.iter_mut() {
            kill_tunnel(*lp, t);
        }
        reg.clear();
        format!("stopped {n} tunnel(s)")
    } else if let Some(mut t) = reg.remove(&port) {
        kill_tunnel(port, &mut t);
        format!("stopped tunnel localhost:{port} -> {}:{}", t.alias, t.remote_port)
    } else {
        return extension_failure(&format!("no tunnel on local port {port}"));
    };
    let mut reply = success_frame();
    put_str(&mut reply, &summary);
    reply
}

/// Establish (or reuse) an ssh -L tunnel to `alias`, returning the local
/// port. Same (alias, remote_port) reuses; our own tunnel on the preferred
/// port with a different target is replaced (last request wins); a foreign
/// process on the port pushes us to an ephemeral one.
fn ensure_tunnel(alias: &str, remote_port: u16) -> Result<u16> {
    let mut reg = tunnels().lock().unwrap();
    prune_dead(&mut reg);
    if let Some((lp, _)) = reg
        .iter()
        .find(|(_, t)| t.alias == alias && t.remote_port == remote_port)
    {
        return Ok(*lp);
    }
    let preferred = remote_port;
    if let Some(mut old) = reg.remove(&preferred) {
        logging::info(format!(
            "port {preferred} held for {}:{}; replacing with {alias}:{remote_port}",
            old.alias, old.remote_port
        ));
        kill_tunnel(preferred, &mut old);
    }
    let local = if port_available(preferred) {
        preferred
    } else {
        ephemeral_port()?
    };

    let mut child = spawn_tunnel(alias, local, remote_port)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect(("127.0.0.1", local)).is_ok() {
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            bail!(
                "ssh tunnel to {alias} exited ({status}) before forwarding came up — check that \
                 `ssh {alias}` works non-interactively"
            );
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("ssh tunnel to {alias} did not come up within 15s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    logging::info(format!(
        "tunnel established: localhost:{local} -> {alias}:{remote_port} (ssh pid {})",
        child.id()
    ));
    reg.insert(
        local,
        Tunnel {
            alias: alias.to_string(),
            remote_port,
            child,
        },
    );
    Ok(local)
}

fn spawn_tunnel(alias: &str, local: u16, remote: u16) -> Result<Child> {
    let ssh = std::env::var_os("BACKCHANNEL_SSH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ssh"));
    // BatchMode: a headless daemon must fail fast, never hang on a prompt.
    // ExitOnForwardFailure: a failed bind must kill the child (detectable),
    // not leave a connected ssh with no forwarding (ssh's silent default).
    Command::new(&ssh)
        .arg("-N")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-L")
        .arg(format!("{local}:127.0.0.1:{remote}"))
        .arg(alias)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {} for the tunnel", ssh.display()))
}

fn port_available(p: u16) -> bool {
    TcpListener::bind(("127.0.0.1", p)).is_ok()
}

fn ephemeral_port() -> Result<u16> {
    Ok(TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port())
}

/// Minimal URL split: (scheme, host, port, path-and-after). Enough for
/// loopback validation and port rewriting; not a general URL parser.
fn split_url(url: &str) -> Option<(String, String, u16, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (h, p) = bracketed.split_once(']')?;
        (h.to_string(), p.strip_prefix(':').and_then(|p| p.parse().ok()))
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        match p.parse::<u16>() {
            Ok(pn) => (h.to_string(), Some(pn)),
            Err(_) => (authority.to_string(), None),
        }
    } else {
        (authority.to_string(), None)
    };
    let default = if scheme == "https" { 443 } else { 80 };
    Some((scheme, host, port.unwrap_or(default), tail.to_string()))
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

/// Tunnel then open: returns (final URL opened, "alias:port" description).
fn proxy_open(url: &str, alias: &str) -> Result<(String, String)> {
    let (scheme, host, port, tail) =
        split_url(url).with_context(|| format!("unparseable URL {url:?}"))?;
    if !is_loopback(&host) {
        bail!(
            "--proxy only forwards the remote host's own loopback; {host:?} is not \
             localhost/127.0.0.1/::1"
        );
    }
    let local = ensure_tunnel(alias, port)?;
    let final_url = if local == port {
        url.to_string()
    } else {
        format!("{scheme}://localhost:{local}{tail}")
    };
    launch::open_url(&final_url)?;
    Ok((final_url, format!("{alias}:{port}")))
}

/// Reduce a remote-supplied filename to a bare, viewable basename: strip
/// any path components (traversal), and refuse extensions the local opener
/// would *execute* rather than display (.command/.terminal/... on macOS,
/// .desktop's Exec= on Linux).
fn safe_basename(raw: &str) -> Result<String> {
    let name = Path::new(raw)
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .filter(|n| n != "." && n != "..")
        .with_context(|| format!("bad filename {raw:?}"))?;
    const EXECUTABLE_EXTS: &[&str] = &["command", "terminal", "tool", "workflow", "app", "desktop"];
    if let Some(ext) = Path::new(&name).extension().and_then(|e| e.to_str()) {
        if EXECUTABLE_EXTS.iter().any(|d| ext.eq_ignore_ascii_case(d)) {
            bail!("refusing to open {name:?}: .{ext} files execute rather than display");
        }
    }
    Ok(name)
}

fn handle_open_file(data: &[u8]) -> Result<String> {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let req = OpenFileRequest::decode(data).context("decoding open-file request")?;
    if req.data.len() > crate::clipboard::MAX_COPY_BYTES {
        bail!("file payload of {} bytes exceeds the limit", req.data.len());
    }
    let name = safe_basename(&req.basename)?;
    // Fresh directory per request: no collisions, meaningful basename
    // preserved for app selection, OS temp reaper handles eventual cleanup.
    let dir = std::env::temp_dir().join("backchannel-open").join(format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let path = dir.join(&name);
    std::fs::write(&path, &req.data).with_context(|| format!("writing {}", path.display()))?;
    launch::open_with_default(&path.to_string_lossy())?;
    Ok(format!(
        "open file {} ({} bytes) from host '{}' -> {}",
        name,
        req.data.len(),
        req.hostname,
        path.display()
    ))
}

/// Bulk transfer for `back open`/`back copy`: fetch the file ourselves over
/// a fresh ssh connection (scp: real session-channel windows, link-speed)
/// instead of squeezing it through the agent channel's 64KB window.
/// Interim progress frames stream back to the client while scp runs.
/// Failures the client can work around are prefixed PULL-FALLBACK so it
/// retries inline instead of giving up.
fn handle_pull(
    data: &[u8],
    peer: Option<peer::PeerInfo>,
    stream: &mut UnixStream,
) -> Result<()> {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let fail = |stream: &mut UnixStream, msg: String| -> Result<()> {
        logging::error(format!("pull failed: {msg}"));
        write_frame(stream, &extension_failure(&msg))?;
        Ok(())
    };

    let req = match PullRequest::decode(data).context("decoding pull request") {
        Ok(r) => r,
        Err(e) => return fail(stream, format!("{e:#}")),
    };
    let (alias, how) = resolve_alias(peer, &req.hostname, &req.user, &req.ssh_connection);

    // Destination name: sanitized (and denylisted) for "open", since it gets
    // handed to the default app; anonymous for "copy", which never opens it.
    let dest_name = match req.disposition.as_str() {
        "open" => match safe_basename(&req.path) {
            Ok(n) => n,
            Err(e) => return fail(stream, format!("{e:#}")),
        },
        "copy" => "payload".to_string(),
        other => return fail(stream, format!("bad disposition {other:?}")),
    };
    let dir = std::env::temp_dir().join("backchannel-open").join(format!(
        "{}-p{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return fail(stream, format!("creating {}: {e}", dir.display()));
    }
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    let dest = dir.join(&dest_name);

    let scp = std::env::var_os("BACKCHANNEL_SCP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("scp"));
    let child = Command::new(&scp)
        .arg("-q")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg(format!("{alias}:{}", req.path))
        .arg(&dest)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return fail(stream, format!("PULL-FALLBACK: spawning {}: {e}", scp.display())),
    };
    logging::info(format!(
        "pull {} from {}:{} (alias via {how}, {} bytes) -> {}",
        req.disposition,
        alias,
        req.path,
        req.size,
        dest.display()
    ));

    // Progress: scp writes the destination in place, so its size is an
    // honest live byte count. A frame every poll doubles as a keepalive.
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                return fail(stream, format!("waiting on scp: {e}"));
            }
        }
        let done = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
        write_frame(stream, &progress_frame(done, req.size))?;
        std::thread::sleep(Duration::from_millis(100));
    };
    if !status.success() {
        let mut stderr = String::new();
        if let Some(mut e) = child.stderr.take() {
            use std::io::Read;
            let _ = e.read_to_string(&mut stderr);
        }
        let _ = std::fs::remove_dir_all(&dir);
        return fail(
            stream,
            format!("PULL-FALLBACK: scp exited with {status}: {}", stderr.trim()),
        );
    }

    let result: Result<String> = match req.disposition.as_str() {
        "open" => launch::open_with_default(&dest.to_string_lossy()).map(|()| {
            format!(
                "pulled + opened {} ({} bytes) from host '{}'",
                dest_name, req.size, req.hostname
            )
        }),
        _ => {
            // copy: read, sniff, clipboard, clean up.
            let outcome = std::fs::read(&dest)
                .map_err(anyhow::Error::from)
                .and_then(|data| {
                    if data.len() > crate::clipboard::MAX_COPY_BYTES {
                        bail!("pulled file exceeds the clipboard size limit");
                    }
                    let kind = crate::clipboard::detect_kind(&data).context(
                        "content is neither UTF-8 text nor a recognized image",
                    )?;
                    crate::clipboard::set(kind, &data)?;
                    Ok(format!(
                        "pulled + copied {kind} ({} bytes) from host '{}'",
                        data.len(),
                        req.hostname
                    ))
                });
            let _ = std::fs::remove_dir_all(&dir);
            outcome
        }
    };
    match result {
        Ok(summary) => {
            logging::info(summary);
            Ok(write_frame(stream, &success_frame())?)
        }
        Err(e) => fail(stream, format!("{e:#}")),
    }
}

fn handle_copy(data: &[u8]) -> Result<String> {
    let req = CopyRequest::decode(data).context("decoding copy request")?;
    if req.data.len() > crate::clipboard::MAX_COPY_BYTES {
        bail!("copy payload of {} bytes exceeds the limit", req.data.len());
    }
    crate::clipboard::set(&req.kind, &req.data)?;
    Ok(format!(
        "copy {} ({} bytes) from host '{}'",
        req.kind,
        req.data.len(),
        req.hostname
    ))
}

/// Decode and act on an open request, writing the reply frame(s) to the
/// client. Returns Err only for socket-level failures; request-level
/// problems become extension_failure replies.
fn handle_open(
    data: &[u8],
    peer: Option<peer::PeerInfo>,
    stream: &mut UnixStream,
) -> Result<()> {
    let fail = |stream: &mut UnixStream, e: &anyhow::Error| -> Result<()> {
        logging::error(format!("open failed: {e:#}"));
        write_frame(stream, &extension_failure(&format!("{e:#}")))?;
        Ok(())
    };

    let req = match OpenRequest::decode(data).context("decoding open request") {
        Ok(r) => r,
        Err(e) => return fail(stream, &e),
    };

    // URLs go to the local browser, not VS Code.
    if let Action::Url { url, proxy } = &req.action {
        if req.wait {
            return fail(stream, &anyhow::anyhow!("--wait is not supported for URLs"));
        }
        let lower = url.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            // A remote must not be able to trigger arbitrary local scheme
            // handlers (file:, ssh:, app-registered schemes, ...).
            return fail(stream, &anyhow::anyhow!("refusing non-http(s) URL {url:?}"));
        }
        if *proxy {
            let (alias, how) = resolve_alias(peer, &req.hostname, &req.user, &req.ssh_connection);
            return match proxy_open(url, &alias) {
                Ok((final_url, target)) => {
                    logging::info(format!(
                        "proxy url {} -> {} (alias '{}' via {})",
                        url, final_url, alias, how
                    ));
                    Ok(write_frame(stream, &success_with_authority(&final_url, &target))?)
                }
                Err(e) => fail(stream, &e),
            };
        }
        logging::info(format!("open url {} from host '{}'", url, req.hostname));
        return match launch::open_url(url) {
            Ok(()) => Ok(write_frame(stream, &success_frame())?),
            Err(e) => fail(stream, &e),
        };
    }

    let (alias, how) = resolve_alias(peer, &req.hostname, &req.user, &req.ssh_connection);
    let args = launch::code_args(&alias, &req.action, req.window, req.wait);
    logging::info(format!(
        "{} from host '{}' (alias '{}' via {}) -> code {}",
        describe(&req.action),
        req.hostname,
        alias,
        how,
        args.join(" ")
    ));

    if !req.wait {
        return match launch::run_code(args) {
            Ok(()) => Ok(write_frame(stream, &success_with_authority(&alias, how))?),
            Err(e) => fail(stream, &e),
        };
    }

    // Wait mode: ack once the CLI is spawned, then hold the reply until the
    // editor closes. The blocked client (and the git/EDITOR flow behind it)
    // unblocks when the final frame lands.
    let waiting = match launch::spawn_code_waiting(&args) {
        Ok(w) => w,
        Err(e) => return fail(stream, &e),
    };
    write_frame(stream, &success_with_authority(&alias, how))?;
    match launch::wait_until_closed(waiting, stream) {
        Ok(()) => {
            logging::info(format!("{} closed; releasing waiter", describe(&req.action)));
            Ok(write_frame(stream, &success_frame())?)
        }
        Err(e) => {
            logging::warn(format!("--wait ended without a clean close: {e:#}"));
            // The client may already be gone; a failed write here is fine.
            let _ = write_frame(stream, &extension_failure(&format!("{e:#}")));
            Ok(())
        }
    }
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
        Action::Url { url, proxy: false } => format!("open url {}", url),
        Action::Url { url, proxy: true } => format!("proxy url {}", url),
    }
}

/// Best source first: the argv of the ssh process that carried the request
/// (the alias exactly as typed), then the user's aliases file (keyed by the
/// remote's hostname or its SSH_CONNECTION server IP), then a user@server_ip
/// authority derived from SSH_CONNECTION — guaranteed reachable, since this
/// very request rode over that endpoint — and only then the bare hostname.
fn resolve_alias(
    peer: Option<peer::PeerInfo>,
    hostname: &str,
    user: &str,
    ssh_connection: &str,
) -> (String, &'static str) {
    match peer {
        Some(p) => match peer::process_argv(p.pid) {
            Some(argv) => match ssh_argv::destination(&argv) {
                Some(dest) => return (dest, "ssh argv"),
                // The argv is the evidence for diagnosing this (mux-rewritten
                // titles, ssh flags we don't know) — log it, don't drop it.
                None => logging::warn(format!(
                    "no ssh destination recoverable from peer argv (pid {}): {:?} — falling back",
                    p.pid, argv
                )),
            },
            None => logging::warn(format!(
                "could not read argv of peer process (pid {}) — falling back",
                p.pid
            )),
        },
        None => logging::warn("no peer credentials on this connection — falling back"),
    }
    if let Some(alias) = alias_lookup(hostname) {
        return (alias, "aliases file");
    }
    let endpoint = parse_ssh_connection(ssh_connection);
    if let Some((ip, _)) = &endpoint {
        if let Some(alias) = alias_lookup(ip) {
            return (alias, "aliases file (by ip)");
        }
    }
    if let Some((ip, port)) = endpoint {
        let mut authority = String::new();
        if !user.is_empty() {
            authority.push_str(user);
            authority.push('@');
        }
        authority.push_str(&ip);
        if port != 22 {
            authority.push_str(&format!(":{port}"));
        }
        return (authority, "SSH_CONNECTION");
    }
    (hostname.trim_end_matches('.').to_string(), "remote hostname")
}

/// "client_ip client_port server_ip server_port" -> (server_ip, server_port)
fn parse_ssh_connection(s: &str) -> Option<(String, u16)> {
    let mut parts = s.split_whitespace();
    let (_client_ip, _client_port) = (parts.next()?, parts.next()?);
    let ip = parts.next()?;
    let port: u16 = parts.next()?.parse().ok()?;
    Some((ip.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::{is_loopback, parse_ssh_connection, split_url};

    #[test]
    fn splits_urls() {
        assert_eq!(
            split_url("http://localhost:8000/docs?q=1"),
            Some(("http".into(), "localhost".into(), 8000, "/docs?q=1".into()))
        );
        assert_eq!(
            split_url("https://127.0.0.1"),
            Some(("https".into(), "127.0.0.1".into(), 443, "".into()))
        );
        assert_eq!(
            split_url("http://localhost"),
            Some(("http".into(), "localhost".into(), 80, "".into()))
        );
        assert_eq!(
            split_url("http://[::1]:3000/x"),
            Some(("http".into(), "::1".into(), 3000, "/x".into()))
        );
        assert_eq!(split_url("not a url"), None);
    }

    #[test]
    fn loopback_hosts() {
        assert!(is_loopback("localhost"));
        assert!(is_loopback("LOCALHOST"));
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("::1"));
        assert!(!is_loopback("example.com"));
        assert!(!is_loopback("192.168.1.10"));
    }

    #[test]
    fn parses_ssh_connection() {
        assert_eq!(
            parse_ssh_connection("198.51.100.15 49263 203.0.113.26 22"),
            Some(("203.0.113.26".into(), 22))
        );
        assert_eq!(
            parse_ssh_connection("fe80::1 5 fe80::2 2222"),
            Some(("fe80::2".into(), 2222))
        );
        assert_eq!(parse_ssh_connection(""), None);
        assert_eq!(parse_ssh_connection("1.2.3.4 5 6.7.8.9"), None);
        assert_eq!(parse_ssh_connection("1.2.3.4 5 6.7.8.9 notaport"), None);
    }
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
