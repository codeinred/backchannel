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

    /// Run `backchannel open` against this daemon, as a remote shim would.
    fn open_cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.arg("open")
            .args(args)
            .env("SSH_AUTH_SOCK", self.sock())
            .env_remove("VSCODE_IPC_HOOK_CLI")
            .env_remove("SSH_CONNECTION");
        cmd
    }

    fn open(&self, args: &[&str]) -> std::process::Output {
        self.open_cmd(args).output().unwrap()
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

    let out = env.open(&[&dir]);
    assert!(out.status.success(), "{out:?}");
    env.await_stub_log("--folder-uri vscode-remote://ssh-remote+");

    let out = env.open(&[&format!("{stub}:3:7")]);
    assert!(out.status.success(), "{out:?}");
    let log = env.await_stub_log(":3:7");
    assert!(log.contains("--remote ssh-remote+"), "{log}");
    assert!(log.contains(&format!("--goto {stub}:3:7")), "{log}");

    let other = env.dir.join("other.txt");
    std::fs::write(&other, "x").unwrap();
    let out = env.open(&["-d", &stub, &other.to_string_lossy()]);
    assert!(out.status.success(), "{out:?}");
    let log = env.await_stub_log("--diff");
    assert!(log.contains(&format!("--diff {stub} {}", other.display())), "{log}");

    let out = env.open(&["-n", &dir]);
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
    let out = env.open(&["-w", &stub]);
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
    let out = env.open(&["-w", &stub]);
    assert!(!out.status.success(), "nonzero editor exit must fail the shim");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("code exited"), "{stderr}");
}

#[test]
fn wait_rejects_multiple_paths() {
    let mut env = TestEnv::new("waitmulti");
    env.write_stub("");
    env.start_daemon(&[]);
    let out = env.open(&["-w", "/tmp/a", "/tmp/b"]);
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
        .open_cmd(&["-w", &stub])
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
    let mut b = Vec::new();
    put_u32(&mut b, 4);
    put_str(&mut b, "default");
    put_u32(&mut b, 0);
    put_str(&mut b, "url");
    put_str(&mut b, "file:///etc/passwd");
    put_str(&mut b, "h");
    put_str(&mut b, "u");
    put_str(&mut b, "");
    send_frame(&mut s, &ext_msg("open@backchannel", &b));
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
