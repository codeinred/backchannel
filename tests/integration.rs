//! End-to-end tests: a real daemon process, real unix sockets, and a stub
//! `code` CLI. The agent wire format is implemented here from scratch (the
//! crate is a binary, not a library) — which doubles as a golden-bytes check
//! that the protocol is what we think it is.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_back");

// ---- wire format helpers (independent reimplementation) ----

const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_EXTENSION: u8 = 27;

fn put_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_be_bytes());
}

fn put_str(b: &mut Vec<u8>, s: &str) {
    put_u32(b, s.len() as u32);
    b.extend_from_slice(s.as_bytes());
}

fn ext_msg(name: &str, data: &[u8]) -> Vec<u8> {
    let mut m = vec![SSH_AGENTC_EXTENSION];
    put_str(&mut m, name);
    m.extend_from_slice(data);
    m
}

fn send_frame(s: &mut UnixStream, payload: &[u8]) {
    s.write_all(&(payload.len() as u32).to_be_bytes()).unwrap();
    s.write_all(payload).unwrap();
}

fn read_frame(s: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn get_str(buf: &[u8], pos: &mut usize) -> String {
    let n = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    let s = String::from_utf8_lossy(&buf[*pos..*pos + n]).into_owned();
    *pos += n;
    s
}

/// Ping the daemon; Some(pid) if a backchannel daemon answers.
fn ping(sock: &Path) -> Option<u32> {
    let mut s = UnixStream::connect(sock).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    send_frame(&mut s, &ext_msg("ping@backchannel", &[]));
    let reply = read_frame(&mut s).ok()?;
    if reply.first() != Some(&SSH_AGENT_SUCCESS) {
        return None;
    }
    let mut pos = 1;
    if get_str(&reply, &mut pos) != "backchannel" {
        return None;
    }
    let _version = get_str(&reply, &mut pos);
    Some(u32::from_be_bytes(reply[pos..pos + 4].try_into().unwrap()))
}

/// Encode an open@backchannel v4 request for a single file.
fn encode_open_file(path: &str, wait: bool, hostname: &str, user: &str, ssh_conn: &str) -> Vec<u8> {
    let mut b = Vec::new();
    put_u32(&mut b, 4);
    put_str(&mut b, "default");
    put_u32(&mut b, wait as u32);
    put_str(&mut b, "open");
    put_str(&mut b, "file");
    put_str(&mut b, path);
    put_u32(&mut b, 0);
    put_u32(&mut b, 0);
    put_str(&mut b, hostname);
    put_str(&mut b, user);
    put_str(&mut b, ssh_conn);
    b
}

/// Encode an open@backchannel v4 request for a URL action.
fn encode_url(url: &str, proxy: bool, hostname: &str) -> Vec<u8> {
    let mut b = Vec::new();
    put_u32(&mut b, 4);
    put_str(&mut b, "default");
    put_u32(&mut b, 0); // wait
    put_str(&mut b, "url");
    put_str(&mut b, url);
    put_u32(&mut b, proxy as u32);
    put_str(&mut b, hostname);
    put_str(&mut b, "testuser");
    put_str(&mut b, "");
    b
}

// ---- test environment ----

struct TestEnv {
    dir: PathBuf,
    daemon: Option<Child>,
}

impl TestEnv {
    fn new(name: &str) -> TestEnv {
        // Base must be short: unix socket paths have a ~104-byte limit.
        let dir = std::env::temp_dir().join(format!("bct-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("agent.sock");
        assert!(
            sock.as_os_str().len() < 100,
            "temp dir too long for a socket path: {}",
            sock.display()
        );
        TestEnv { dir, daemon: None }
    }

    fn sock(&self) -> PathBuf {
        self.dir.join("agent.sock")
    }

    /// Install the stub `code` CLI. Every invocation appends its argv to
    /// code-stub.log; `body` runs afterwards (e.g. sleeps for --wait tests).
    fn write_stub(&self, body: &str) {
        let path = self.dir.join("code-stub.sh");
        let script = format!(
            "#!/bin/sh\nlog=\"$(dirname \"$0\")/code-stub.log\"\necho \"$@\" >> \"$log\"\n{body}\n"
        );
        std::fs::write(&path, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn start_daemon(&mut self, extra_env: &[(&str, &str)]) {
        let mut cmd = Command::new(BIN);
        cmd.args(["daemon", "--foreground"])
            .env("BACKCHANNEL_DIR", &self.dir)
            .env("BACKCHANNEL_CODE", self.dir.join("code-stub.sh"))
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        self.daemon = Some(cmd.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        while ping(&self.sock()).is_none() {
            assert!(Instant::now() < deadline, "daemon did not come up");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Run a `back <sub>` client against this daemon, as a remote would.
    fn client_cmd(&self, sub: &str, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.arg(sub)
            .args(args)
            .env("SSH_AUTH_SOCK", self.sock())
            .env_remove("VSCODE_IPC_HOOK_CLI")
            .env_remove("SSH_CONNECTION");
        cmd
    }

    fn code(&self, args: &[&str]) -> std::process::Output {
        self.client_cmd("code", args).output().unwrap()
    }

    fn open(&self, args: &[&str]) -> std::process::Output {
        self.client_cmd("open", args).output().unwrap()
    }

    fn stub_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("code-stub.log")).unwrap_or_default()
    }

    fn await_stub_log(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let log = self.stub_log();
            if log.contains(needle) {
                return log;
            }
            assert!(
                Instant::now() < deadline,
                "stub log never contained {needle:?}; log so far:\n{log}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            // Graceful first: the daemon reaps its tunnel children on a
            // shutdown request; a bare SIGKILL would leak them (and a leaked
            // listener can poison later runs' ports).
            if let Ok(mut s) = UnixStream::connect(self.sock()) {
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                send_frame(&mut s, &ext_msg("shutdown@backchannel", &[]));
                let _ = read_frame(&mut s);
            }
            let _ = d.kill();
            let _ = d.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---- the tests ----

#[test]
fn opens_folder_file_and_diff() {
    let mut env = TestEnv::new("open");
    env.write_stub("");
    env.start_daemon(&[]);

    let dir = env.dir.to_string_lossy().into_owned();
    let stub = env.dir.join("code-stub.sh").to_string_lossy().into_owned();

    let out = env.code(&[&dir]);
    assert!(out.status.success(), "{out:?}");
    env.await_stub_log("--folder-uri vscode-remote://ssh-remote+");

    let out = env.code(&[&format!("{stub}:3:7")]);
    assert!(out.status.success(), "{out:?}");
    let log = env.await_stub_log(":3:7");
    assert!(log.contains("--remote ssh-remote+"), "{log}");
    assert!(log.contains(&format!("--goto {stub}:3:7")), "{log}");

    let other = env.dir.join("other.txt");
    std::fs::write(&other, "x").unwrap();
    let out = env.code(&["-d", &stub, &other.to_string_lossy()]);
    assert!(out.status.success(), "{out:?}");
    let log = env.await_stub_log("--diff");
    assert!(log.contains(&format!("--diff {stub} {}", other.display())), "{log}");

    let out = env.code(&["-n", &dir]);
    assert!(out.status.success(), "{out:?}");
    env.await_stub_log("--new-window");
}

#[test]
fn wait_blocks_until_editor_closes() {
    let mut env = TestEnv::new("waitok");
    env.write_stub(r#"case " $* " in *" --wait "*) sleep 1;; esac"#);
    env.start_daemon(&[]);

    let stub = env.dir.join("code-stub.sh").to_string_lossy().into_owned();
    let start = Instant::now();
    let out = env.code(&["-w", &stub]);
    let elapsed = start.elapsed();

    assert!(out.status.success(), "{out:?}");
    assert!(
        elapsed >= Duration::from_millis(900),
        "returned in {elapsed:?}; --wait did not block"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("waiting until closed"), "{stderr}");
}

#[test]
fn wait_propagates_editor_failure() {
    let mut env = TestEnv::new("waitfail");
    env.write_stub(r#"case " $* " in *" --wait "*) sleep 0.2; exit 7;; esac"#);
    env.start_daemon(&[]);

    let stub = env.dir.join("code-stub.sh").to_string_lossy().into_owned();
    let out = env.code(&["-w", &stub]);
    assert!(!out.status.success(), "nonzero editor exit must fail the shim");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("code exited"), "{stderr}");
}

#[test]
fn wait_rejects_multiple_paths() {
    let mut env = TestEnv::new("waitmulti");
    env.write_stub("");
    env.start_daemon(&[]);
    let out = env.code(&["-w", "/tmp/a", "/tmp/b"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("exactly one path"), "{stderr}");
}

#[test]
fn wait_disconnect_kills_waiting_cli() {
    let mut env = TestEnv::new("waitdisc");
    env.write_stub(
        r#"case " $* " in *" --wait "*) echo $$ > "$(dirname "$0")/stub.pid"; exec sleep 30;; esac"#,
    );
    env.start_daemon(&[]);

    let stub = env.dir.join("code-stub.sh").to_string_lossy().into_owned();
    let mut client = env
        .client_cmd("code", &["-w", &stub])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Wait for the stub CLI to be running, then kill the client mid-wait.
    let pid_file = env.dir.join("stub.pid");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !pid_file.exists() {
        assert!(Instant::now() < deadline, "stub never started");
        std::thread::sleep(Duration::from_millis(25));
    }
    let stub_pid: i32 = std::fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();

    client.kill().unwrap();
    client.wait().unwrap();

    // The daemon must notice the EOF and reap the waiting CLI.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if unsafe { libc::kill(stub_pid, 0) } != 0 {
            break; // gone
        }
        assert!(
            Instant::now() < deadline,
            "daemon never killed the waiting code CLI (pid {stub_pid})"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn frame_pipelined_during_wait_survives() {
    let mut env = TestEnv::new("pipeline");
    env.write_stub(r#"case " $* " in *" --wait "*) sleep 1;; esac"#);
    env.start_daemon(&[]);

    let stub = env.dir.join("code-stub.sh").to_string_lossy().into_owned();
    let mut s = UnixStream::connect(env.sock()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    let open = encode_open_file(&stub, true, "testhost", "tester", "");
    send_frame(&mut s, &ext_msg("open@backchannel", &open));

    // Ack arrives once the CLI is spawned, carrying the resolved authority
    // (hostname fallback here: the peer is this test binary, not ssh).
    let ack = read_frame(&mut s).unwrap();
    assert_eq!(ack.first(), Some(&SSH_AGENT_SUCCESS), "expected spawn ack");
    let mut pos = 1;
    assert_eq!(get_str(&ack, &mut pos), "testhost");
    assert_eq!(get_str(&ack, &mut pos), "remote hostname");

    // ...now pipeline a ping while the wait is in flight. MSG_PEEK-based
    // watching must leave it queued, not corrupt the framing.
    send_frame(&mut s, &ext_msg("ping@backchannel", &[]));

    let start = Instant::now();
    let final_reply = read_frame(&mut s).unwrap();
    assert_eq!(final_reply, [SSH_AGENT_SUCCESS], "wait should resolve cleanly");
    assert!(
        start.elapsed() >= Duration::from_millis(700),
        "final reply arrived before the editor closed"
    );

    let ping_reply = read_frame(&mut s).unwrap();
    let mut pos = 1;
    assert_eq!(ping_reply.first(), Some(&SSH_AGENT_SUCCESS));
    assert_eq!(get_str(&ping_reply, &mut pos), "backchannel");
}

#[test]
fn proxies_agent_traffic_verbatim() {
    let mut env = TestEnv::new("proxy");
    env.write_stub("");

    // A fake upstream agent: answers REQUEST_IDENTITIES (11) with an empty
    // IDENTITIES_ANSWER (12, nkeys=0) and failure (5) otherwise.
    let upstream_path = env.dir.join("upstream.sock");
    let listener = UnixListener::bind(&upstream_path).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { break };
            std::thread::spawn(move || {
                while let Ok(frame) = read_frame(&mut c) {
                    let reply: &[u8] = if frame == [11] { &[12, 0, 0, 0, 0] } else { &[5] };
                    send_frame(&mut c, reply);
                }
            });
        }
    });

    let upstream = upstream_path.to_string_lossy().into_owned();
    env.start_daemon(&[("SSH_AUTH_SOCK", upstream.as_str())]);

    let mut s = UnixStream::connect(env.sock()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    send_frame(&mut s, &[11]);
    assert_eq!(read_frame(&mut s).unwrap(), [12, 0, 0, 0, 0]);

    // And backchannel extensions are still intercepted, not proxied.
    send_frame(&mut s, &ext_msg("ping@backchannel", &[]));
    let reply = read_frame(&mut s).unwrap();
    let mut pos = 1;
    assert_eq!(get_str(&reply, &mut pos), "backchannel");
}

#[test]
fn ssh_connection_provides_fallback_authority() {
    let mut env = TestEnv::new("sshconn");
    env.write_stub("");
    env.start_daemon(&[]);

    let file = env.dir.join("f.txt");
    std::fs::write(&file, "x").unwrap();
    let mut s = UnixStream::connect(env.sock()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let open = encode_open_file(
        &file.to_string_lossy(),
        false,
        "unresolvable-host",
        "tester",
        "198.51.100.15 49263 203.0.113.26 22",
    );
    send_frame(&mut s, &ext_msg("open@backchannel", &open));
    let reply = read_frame(&mut s).unwrap();
    assert_eq!(reply.first(), Some(&SSH_AGENT_SUCCESS));
    let mut pos = 1;
    assert_eq!(get_str(&reply, &mut pos), "tester@203.0.113.26");
    assert_eq!(get_str(&reply, &mut pos), "SSH_CONNECTION");

    let log = env.await_stub_log("--remote");
    assert!(
        log.contains("--remote ssh-remote+tester@203.0.113.26"),
        "expected SSH_CONNECTION-derived authority; got:\n{log}"
    );
}

#[test]
fn urls_open_in_local_browser() {
    let mut env = TestEnv::new("url");
    env.write_stub("");
    // Opener stub records what would reach the browser.
    let opener = env.dir.join("opener.sh");
    std::fs::write(
        &opener,
        "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/opener.log\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&opener, std::fs::Permissions::from_mode(0o755)).unwrap();
    let opener_str = opener.to_string_lossy().into_owned();
    env.start_daemon(&[("BACKCHANNEL_OPENER", opener_str.as_str())]);

    let out = env.open(&["https://example.com/a?b=1"]);
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("local browser"),
        "{out:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let log = std::fs::read_to_string(env.dir.join("opener.log")).unwrap_or_default();
        if log.contains("https://example.com/a?b=1") {
            break;
        }
        assert!(Instant::now() < deadline, "opener never invoked; log: {log}");
        std::thread::sleep(Duration::from_millis(25));
    }

    // Non-http(s) schemes must be refused by the daemon, not opened.
    let mut s = UnixStream::connect(env.sock()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    send_frame(
        &mut s,
        &ext_msg("open@backchannel", &encode_url("file:///etc/passwd", false, "h")),
    );
    let reply = read_frame(&mut s).unwrap();
    assert_eq!(reply.first(), Some(&28), "expected extension failure, got {reply:?}");

    // The `code` shim points at `back open` instead of opening URLs.
    let code_link = env.dir.join("code");
    std::os::unix::fs::symlink(BIN, &code_link).unwrap();
    let out = Command::new(&code_link)
        .arg("https://example.com")
        .env("SSH_AUTH_SOCK", env.sock())
        .env_remove("VSCODE_IPC_HOOK_CLI")
        .env_remove("SSH_CONNECTION")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("back open"),
        "{out:?}"
    );
}

fn write_clipboard_stub(env: &TestEnv) -> String {
    // Records the kind as an argv line and the payload verbatim.
    let stub = env.dir.join("clip.sh");
    std::fs::write(
        &stub,
        "#!/bin/sh\necho \"$1\" >> \"$(dirname \"$0\")/clip.log\"\ncat > \"$(dirname \"$0\")/clip.bin\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    stub.to_string_lossy().into_owned()
}

#[test]
fn copies_text_and_images_through_the_channel() {
    let mut env = TestEnv::new("copy");
    env.write_stub("");
    let clip = write_clipboard_stub(&env);
    env.start_daemon(&[("BACKCHANNEL_CLIPBOARD", clip.as_str())]);

    // Text from stdin.
    let mut child = Command::new(BIN)
        .arg("copy")
        .env("SSH_AUTH_SOCK", env.sock())
        .env_remove("SSH_CONNECTION")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all("hello clipboard: héllo\n".as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        std::fs::read(env.dir.join("clip.bin")).unwrap(),
        "hello clipboard: héllo\n".as_bytes()
    );
    assert!(std::fs::read_to_string(env.dir.join("clip.log")).unwrap().contains("text"));

    // Image from a file (PNG magic is enough for detection).
    let png: Vec<u8> = [b"\x89PNG\r\n\x1a\n".as_slice(), &[7u8; 300]].concat();
    let img = env.dir.join("shot.png");
    std::fs::write(&img, &png).unwrap();
    let out = Command::new(BIN)
        .arg("copy")
        .arg(&img)
        .env("SSH_AUTH_SOCK", env.sock())
        .env_remove("SSH_CONNECTION")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read(env.dir.join("clip.bin")).unwrap(), png);
    assert!(std::fs::read_to_string(env.dir.join("clip.log")).unwrap().contains("image/png"));
}

#[test]
fn copy_sets_local_clipboard_without_a_channel() {
    let env = TestEnv::new("copylocal");
    let clip = write_clipboard_stub(&env);
    let mut child = Command::new(BIN)
        .arg("copy")
        .env("BACKCHANNEL_CLIPBOARD", &clip)
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_CLIENT")
        .env_remove("SSH_TTY")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"local text").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(std::fs::read(env.dir.join("clip.bin")).unwrap(), b"local text");
}

#[test]
fn copy_rejects_oversized_and_binary_junk() {
    let env = TestEnv::new("copybad");
    let clip = write_clipboard_stub(&env);
    let base_env = |cmd: &mut Command| {
        cmd.env("BACKCHANNEL_CLIPBOARD", &clip)
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_CONNECTION")
            .env_remove("SSH_CLIENT")
            .env_remove("SSH_TTY");
    };

    let big = env.dir.join("big.txt");
    std::fs::write(&big, vec![b'a'; 201 * 1024 * 1024]).unwrap();
    let mut cmd = Command::new(BIN);
    base_env(cmd.arg("copy").arg(&big));
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("exceeds"), "{out:?}");

    let junk = env.dir.join("junk.bin");
    std::fs::write(&junk, [0x00u8, 0xFF, 0xFE, 0x01]).unwrap();
    let mut cmd = Command::new(BIN);
    base_env(cmd.arg("copy").arg(&junk));
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("neither UTF-8 text nor a recognized image"),
        "{out:?}"
    );
    assert!(!env.dir.join("clip.bin").exists(), "nothing should have been copied");
}

/// A stand-in for `ssh -N -L`: parses the -L spec, binds the local port,
/// and accepts-and-closes forever. Lets tunnel lifecycle be tested with no
/// network or real ssh.
fn write_tunnel_stub(env: &TestEnv) -> String {
    let stub = env.dir.join("ssh-stub.sh");
    let script = r#"#!/bin/sh
echo "$@" >> "$(dirname "$0")/ssh.log"
prev=""
for a in "$@"; do
  if [ "$prev" = "-L" ]; then spec="$a"; fi
  prev="$a"
done
exec python3 -c '
import socket, sys
port = int(sys.argv[1].split(":")[0])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(5)
while True:
    c, _ = s.accept()
    c.close()
' "$spec"
"#;
    std::fs::write(&stub, script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    stub.to_string_lossy().into_owned()
}

#[test]
fn proxy_tunnels_replaces_and_stops() {
    let mut env = TestEnv::new("tun");
    env.write_stub("");
    let ssh_stub = write_tunnel_stub(&env);
    let opener = env.dir.join("opener.sh");
    std::fs::write(
        &opener,
        "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/opener.log\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&opener, std::fs::Permissions::from_mode(0o755)).unwrap();
    let opener_str = opener.to_string_lossy().into_owned();
    env.start_daemon(&[
        ("BACKCHANNEL_SSH", ssh_stub.as_str()),
        ("BACKCHANNEL_OPENER", opener_str.as_str()),
    ]);

    // Establish a tunnel via the normal client path, on a port that is
    // verifiably free right now (fixed ports poison reruns if anything leaks).
    let port = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        l.local_addr().unwrap().port()
    };
    let url = format!("http://localhost:{port}/x");
    let out = env.open(&["--proxy", &url]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tunneled to"), "{stdout}");
    let ssh_log = std::fs::read_to_string(env.dir.join("ssh.log")).unwrap_or_else(|e| {
        let listing: Vec<_> = std::fs::read_dir(&env.dir)
            .unwrap()
            .flatten()
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .collect();
        let dlog = std::fs::read_to_string(env.dir.join("daemon.log")).unwrap_or_default();
        panic!("no ssh.log ({e}); dir: {listing:?}\ndaemon.log:\n{dlog}");
    });
    assert!(ssh_log.contains(&format!("-L {port}:127.0.0.1:{port}")), "{ssh_log}");
    // The opener is spawned asynchronously after the reply — poll for it.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let log = std::fs::read_to_string(env.dir.join("opener.log")).unwrap_or_default();
        if log.contains(&url) {
            break;
        }
        assert!(Instant::now() < deadline, "opener never saw {url}; log: {log}");
        std::thread::sleep(Duration::from_millis(25));
    }

    // Same target again: reused, not respawned.
    let out = env.open(&["--proxy", &url]);
    assert!(out.status.success(), "{out:?}");
    let ssh_log = std::fs::read_to_string(env.dir.join("ssh.log")).unwrap();
    assert_eq!(ssh_log.matches("-L").count(), 1, "tunnel should be reused:\n{ssh_log}");

    // A different host wanting the same port: ours gets torn down, theirs
    // takes over.
    let mut s = UnixStream::connect(env.sock()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    send_frame(
        &mut s,
        &ext_msg("open@backchannel", &encode_url(&url, true, "otherhost")),
    );
    let reply = read_frame(&mut s).unwrap();
    assert_eq!(reply.first(), Some(&SSH_AGENT_SUCCESS), "{reply:?}");
    let ssh_log = std::fs::read_to_string(env.dir.join("ssh.log")).unwrap();
    assert_eq!(ssh_log.matches("-L").count(), 2, "expected respawn:\n{ssh_log}");
    assert!(ssh_log.contains("otherhost"), "{ssh_log}");

    // list shows the new owner; stop tears it down and frees the port.
    let out = Command::new(BIN)
        .args(["proxy", "list"])
        .env("SSH_AUTH_SOCK", env.sock())
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(listing.contains("otherhost"), "{listing}");
    assert!(!listing.contains("testhost"), "{listing}");

    let out = Command::new(BIN)
        .args(["proxy", "stop", &port.to_string()])
        .env("SSH_AUTH_SOCK", env.sock())
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("stopped"), "{out:?}");

    let out = Command::new(BIN)
        .args(["proxy", "list"])
        .env("SSH_AUTH_SOCK", env.sock())
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("no active tunnels"), "{out:?}");

    // Port actually released.
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "port {port} not released");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn proxy_rejects_non_loopback() {
    let mut env = TestEnv::new("proxyloop");
    env.write_stub("");
    let ssh_stub = write_tunnel_stub(&env);
    env.start_daemon(&[("BACKCHANNEL_SSH", ssh_stub.as_str())]);
    let out = env.open(&["--proxy", "http://internal.example.com:8080/"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("loopback"),
        "{out:?}"
    );
    assert!(!env.dir.join("ssh.log").exists(), "no tunnel should have been attempted");
}

fn encode_openfile(basename: &str, hostname: &str, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    put_u32(&mut b, 1);
    put_str(&mut b, basename);
    put_str(&mut b, hostname);
    b.extend_from_slice(data);
    b
}

#[test]
fn open_transfers_files_to_local_default_app() {
    let mut env = TestEnv::new("openfile");
    env.write_stub("");
    let opener = env.dir.join("opener.sh");
    std::fs::write(
        &opener,
        "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/opener.log\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&opener, std::fs::Permissions::from_mode(0o755)).unwrap();
    let opener_str = opener.to_string_lossy().into_owned();
    env.start_daemon(&[("BACKCHANNEL_OPENER", opener_str.as_str())]);

    let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><text>flame</text></svg>";
    let src = env.dir.join("graph.svg");
    std::fs::write(&src, svg).unwrap();

    // Plain path and file:// URL forms both transfer.
    for target in [
        src.to_string_lossy().into_owned(),
        format!("file://{}", src.display()),
    ] {
        std::fs::remove_file(env.dir.join("opener.log")).ok();
        let out = env.open(&[&target]);
        assert!(out.status.success(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("default app"),
            "{out:?}"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let opened = loop {
            let log = std::fs::read_to_string(env.dir.join("opener.log")).unwrap_or_default();
            if !log.trim().is_empty() {
                break log.trim().to_string();
            }
            assert!(Instant::now() < deadline, "opener never invoked");
            std::thread::sleep(Duration::from_millis(25));
        };
        // The opened path is a *transferred copy*: same basename and bytes,
        // different location.
        let opened = Path::new(&opened);
        assert_eq!(opened.file_name().unwrap(), "graph.svg");
        assert_ne!(opened, src);
        assert_eq!(std::fs::read(opened).unwrap(), svg);
    }

    // Directories are refused with a pointer at `back code`.
    let out = env.open(&[&env.dir.to_string_lossy()]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("back code"),
        "{out:?}"
    );
}

#[test]
fn pull_transfers_via_scp_and_falls_back_inline() {
    let mut env = TestEnv::new("pull");
    env.write_stub("");
    let opener = env.dir.join("opener.sh");
    std::fs::write(
        &opener,
        "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/opener.log\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&opener, std::fs::Permissions::from_mode(0o755)).unwrap();
    // scp stand-in: strips "alias:" from the source and copies locally,
    // slowly enough (two chunks) that a progress frame can flow.
    let scp = env.dir.join("scp-stub.sh");
    std::fs::write(
        &scp,
        r#"#!/bin/sh
echo "$@" >> "$(dirname "$0")/scp.log"
for a in "$@"; do
  case "$a" in *:*) src="${a#*:}";; esac
  dest="$a"
done
head -c 100000 "$src" > "$dest"
sleep 0.3
cat "$src" > "$dest"
"#,
    )
    .unwrap();
    std::fs::set_permissions(&scp, std::fs::Permissions::from_mode(0o755)).unwrap();
    let opener_str = opener.to_string_lossy().into_owned();
    let scp_str = scp.to_string_lossy().into_owned();
    env.start_daemon(&[
        ("BACKCHANNEL_OPENER", opener_str.as_str()),
        ("BACKCHANNEL_SCP", scp_str.as_str()),
    ]);

    let payload: Vec<u8> = (0..500_000u32).flat_map(|i| i.to_le_bytes()).collect();
    let src = env.dir.join("big.svg");
    std::fs::write(&src, &payload).unwrap();

    // Threshold 1: everything pulls.
    let out = env
        .client_cmd("open", &[&src.to_string_lossy()])
        .env("BACKCHANNEL_PULL_THRESHOLD", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let scp_log = std::fs::read_to_string(env.dir.join("scp.log")).unwrap();
    assert!(scp_log.contains(&format!(":{}", src.display())), "{scp_log}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let log = std::fs::read_to_string(env.dir.join("opener.log")).unwrap_or_default();
        if !log.trim().is_empty() {
            let opened = log.trim().to_string();
            assert!(opened.ends_with("/big.svg"), "{opened}");
            assert_eq!(std::fs::read(&opened).unwrap(), payload, "pulled bytes differ");
            break;
        }
        assert!(Instant::now() < deadline, "opener never invoked");
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn pull_fallback_when_daemon_cannot_scp() {
    let mut env = TestEnv::new("pullfb");
    env.write_stub("");
    let opener = env.dir.join("opener.sh");
    std::fs::write(
        &opener,
        "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/opener.log\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&opener, std::fs::Permissions::from_mode(0o755)).unwrap();
    let opener_str = opener.to_string_lossy().into_owned();
    // Daemon has a broken scp: every pull must fall back to inline.
    env.start_daemon(&[
        ("BACKCHANNEL_OPENER", opener_str.as_str()),
        ("BACKCHANNEL_SCP", "/nonexistent/scp"),
    ]);

    let payload = vec![7u8; 200_000];
    let src = env.dir.join("fb.png");
    let png: Vec<u8> = [b"\x89PNG\r\n\x1a\n".as_slice(), &payload].concat();
    std::fs::write(&src, &png).unwrap();

    let out = env
        .client_cmd("open", &[&src.to_string_lossy()])
        .env("BACKCHANNEL_PULL_THRESHOLD", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("transferring inline"),
        "{out:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let log = std::fs::read_to_string(env.dir.join("opener.log")).unwrap_or_default();
        if !log.trim().is_empty() {
            assert_eq!(std::fs::read(log.trim()).unwrap(), png);
            break;
        }
        assert!(Instant::now() < deadline, "opener never invoked");
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn openfile_sanitizes_names_and_refuses_executables() {
    let mut env = TestEnv::new("opensafe");
    env.write_stub("");
    let opener = env.dir.join("opener.sh");
    std::fs::write(
        &opener,
        "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/opener.log\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&opener, std::fs::Permissions::from_mode(0o755)).unwrap();
    let opener_str = opener.to_string_lossy().into_owned();
    env.start_daemon(&[("BACKCHANNEL_OPENER", opener_str.as_str())]);

    // Path traversal in the basename is neutralized to the final component.
    let mut s = UnixStream::connect(env.sock()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    send_frame(
        &mut s,
        &ext_msg(
            "openfile@backchannel",
            &encode_openfile("../../escape.svg", "h", b"<svg/>"),
        ),
    );
    assert_eq!(read_frame(&mut s).unwrap().first(), Some(&SSH_AGENT_SUCCESS));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let log = std::fs::read_to_string(env.dir.join("opener.log")).unwrap_or_default();
        if !log.trim().is_empty() {
            let opened = log.trim().to_string();
            assert!(opened.ends_with("/escape.svg"), "{opened}");
            assert!(!opened.contains(".."), "{opened}");
            break;
        }
        assert!(Instant::now() < deadline, "opener never invoked");
        std::thread::sleep(Duration::from_millis(25));
    }

    // Executable-flavored extensions are refused outright.
    for name in ["evil.command", "evil.desktop", "Evil.APP"] {
        send_frame(
            &mut s,
            &ext_msg("openfile@backchannel", &encode_openfile(name, "h", b"x")),
        );
        let reply = read_frame(&mut s).unwrap();
        assert_eq!(reply.first(), Some(&28), "{name} should be refused: {reply:?}");
    }
}

#[test]
fn replace_takes_over_and_shutdown_works() {
    let mut env = TestEnv::new("replace");
    env.write_stub("");
    env.start_daemon(&[]);
    let first_pid = ping(&env.sock()).unwrap();

    // --replace daemonizes; poll until the pid changes.
    let status = Command::new(BIN)
        .args(["daemon", "--replace"])
        .env("BACKCHANNEL_DIR", &env.dir)
        .env_remove("SSH_AUTH_SOCK")
        .status()
        .unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    let second_pid = loop {
        if let Some(pid) = ping(&env.sock()) {
            if pid != first_pid {
                break pid;
            }
        }
        assert!(Instant::now() < deadline, "replacement daemon never answered");
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_ne!(first_pid, second_pid);

    // Shut the (detached) replacement down via the extension and confirm it
    // removes its socket.
    let mut s = UnixStream::connect(env.sock()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    send_frame(&mut s, &ext_msg("shutdown@backchannel", &[]));
    let _ = read_frame(&mut s);
    let deadline = Instant::now() + Duration::from_secs(5);
    while env.sock().exists() {
        assert!(Instant::now() < deadline, "socket not removed on shutdown");
        std::thread::sleep(Duration::from_millis(25));
    }
}
