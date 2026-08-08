#!/usr/bin/env python3
"""End-to-end tests against a real host over real ssh.

    python3 tests/live.py <host>        (or: just live-test <host>)

The stub-based integration suite (tests/integration.rs) can't vouch for real
ssh behavior — mux masters stealing forwardings under ControlPersist, sshd
option handling, scp over a fresh connection. This harness can. It runs a
*hermetic* daemon (own BACKCHANNEL_DIR, stubbed opener/code/clipboard so no
windows pop and nothing touches the real clipboard) but connects through the
real ssh stack: your ssh config, real network, real sshd, and the real `back`
binary installed on <host>.

Requirements:
  - `back` deployed on <host> at a matching version (just deploy-dev <host>)
  - non-interactive ssh auth to <host>
  - python3 on <host>

Nothing here touches the production daemon or its socket: the session ssh
gets `-o ForwardAgent=<hermetic sock>` and a private control path.
"""

import argparse
import hashlib
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

CHECKS = []  # (name, ok, detail)


def check(name, ok, detail=""):
    CHECKS.append((name, ok, detail))
    mark = "\033[32m✓\033[0m" if ok else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + ("" if ok else f"\n      {detail}"))
    return ok


def fatal(msg):
    print(f"\nFATAL: {msg}", file=sys.stderr)
    sys.exit(2)


def wait_for(cond, timeout=10, interval=0.1, desc="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        v = cond()
        if v:
            return v
        time.sleep(interval)
    return None


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Harness:
    def __init__(self, host, binary, keep):
        self.host = host
        self.binary = os.path.abspath(binary)
        self.keep = keep
        # A unix socket path must fit sun_path (~104 bytes on macOS); the
        # default TMPDIR is fine, but fall back to /tmp if it's unusually deep.
        base = tempfile.gettempdir()
        if len(base) > 60:
            base = "/tmp"
        self.tmp = tempfile.mkdtemp(prefix="bc-live-", dir=base)
        self.bcdir = os.path.join(self.tmp, "bc")
        self.logs = os.path.join(self.tmp, "logs")
        os.makedirs(self.bcdir)
        os.makedirs(self.logs)
        self.ctl = os.path.join(self.tmp, "cm")
        self.sock = os.path.join(self.bcdir, "agent.sock")
        self.daemon = None
        self.master = None
        self.remote_back = None
        self.remote_tmp = None
        self.http_pid = None

    # ---- local plumbing ------------------------------------------------

    def write_stub(self, name, body):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, 0o755)
        return path

    def start_daemon(self):
        opener = self.write_stub(
            "opener.sh", f'#!/bin/sh\necho "$@" >> {self.logs}/opener.log\n'
        )
        # --wait blocks until the "editor" exits: hold the daemon for a beat
        # so blocking is observable, and fail (exit 7) when the target is
        # named fail-* so the error path can be exercised too.
        code = self.write_stub(
            "code.sh",
            f'#!/bin/sh\necho "$@" >> {self.logs}/code.log\n'
            f'case " $* " in *" --wait "*)\n'
            f'  sleep 1\n'
            f'  case " $* " in *fail-*) exit 7;; esac\n'
            f'esac\n',
        )
        clip = self.write_stub(
            "clipboard.sh",
            f'#!/bin/sh\nprintf %s "$1" > {self.logs}/clip.kind\ncat > {self.logs}/clip.bin\n',
        )
        env = dict(
            os.environ,
            BACKCHANNEL_DIR=self.bcdir,
            BACKCHANNEL_OPENER=opener,
            BACKCHANNEL_CODE=code,
            BACKCHANNEL_CLIPBOARD=clip,
        )
        self.daemon = subprocess.Popen(
            [self.binary, "daemon", "--foreground"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=open(os.path.join(self.logs, "daemon.stderr"), "w"),
        )
        if not wait_for(lambda: os.path.exists(self.sock), timeout=5):
            fatal(f"daemon socket never appeared; see {self.logs}/daemon.stderr")

    def daemon_log(self):
        try:
            with open(os.path.join(self.bcdir, "daemon.log")) as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def stub_log(self, name):
        try:
            with open(os.path.join(self.logs, name)) as f:
                return f.read()
        except FileNotFoundError:
            return ""

    # ---- ssh plumbing ----------------------------------------------------

    def start_master(self):
        # A private master: -o ForwardAgent points every session at the
        # hermetic daemon (command line beats any ForwardAgent in the user's
        # config), and ControlPersist=no keeps the master a foreground child
        # we own, rather than a self-backgrounding one.
        self.master = subprocess.Popen(
            [
                "ssh",
                "-M",
                "-N",
                "-S", self.ctl,
                "-o", f"ForwardAgent={self.sock}",
                "-o", "ControlPersist=no",
                "-o", "BatchMode=yes",
                self.host,
            ],
            stdin=subprocess.DEVNULL,
        )

        def up():
            r = subprocess.run(
                ["ssh", "-S", self.ctl, "-O", "check", self.host],
                capture_output=True,
            )
            return r.returncode == 0

        if not wait_for(up, timeout=20, interval=0.3):
            fatal(f"ssh master to {self.host} did not come up (BatchMode auth?)")

    def ssh(self, cmd, timeout=30):
        """Run a command on the host through the shared master."""
        return subprocess.run(
            ["ssh", "-S", self.ctl, self.host, "--", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def back(self, argstr, timeout=60):
        return self.ssh(f"{self.remote_back} {argstr}", timeout=timeout)

    # ---- setup / teardown -------------------------------------------------

    def find_remote_back(self):
        # Non-interactive ssh often lacks the login PATH; probe common spots.
        probe = (
            "command -v back || ls "
            "$HOME/.local/cargo/bin/back $HOME/.cargo/bin/back "
            "$HOME/.local/bin/back 2>/dev/null | head -1"
        )
        r = self.ssh(probe)
        path = r.stdout.strip().splitlines()
        if not path:
            fatal(
                f"no `back` binary found on {self.host} — deploy it first: "
                f"just deploy-dev {self.host}"
            )
        self.remote_back = path[0]

    def check_versions(self, skip):
        local = subprocess.run(
            [self.binary, "--version"], capture_output=True, text=True
        ).stdout.strip()
        remote = self.back("--version").stdout.strip()
        print(f"  local:  {local} ({self.binary})")
        print(f"  remote: {remote} ({self.remote_back})")
        if local != remote and not skip:
            fatal(
                f"version mismatch — deploy first (just deploy-dev {self.host}) "
                f"or pass --skip-version-check"
            )

    def cleanup(self):
        if self.http_pid:
            self.ssh(f"kill {self.http_pid} 2>/dev/null; true")
        if self.remote_tmp:
            self.ssh(f"rm -rf {self.remote_tmp}")
        if self.master:
            subprocess.run(
                ["ssh", "-S", self.ctl, "-O", "exit", self.host],
                capture_output=True,
            )
            try:
                self.master.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.master.kill()
        if self.daemon:
            # Graceful shutdown tears down any leftover tunnel children.
            subprocess.run(
                [self.binary, "proxy", "stop", "--all"],
                env=dict(os.environ, SSH_AUTH_SOCK=self.sock),
                capture_output=True,
            )
            self.daemon.send_signal(signal.SIGTERM)
            try:
                self.daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
        failed = any(not ok for _, ok, _ in CHECKS)
        if self.keep or failed:
            print(f"\nwork dir kept: {self.tmp}")
        else:
            shutil.rmtree(self.tmp, ignore_errors=True)


# ---- the tests -------------------------------------------------------------


def test_copy(h):
    print("\ncopy:")
    nonce = f"backchannel live test {random.randrange(1 << 48):x}"
    r = h.ssh(f"printf %s '{nonce}' | {h.remote_back} copy")
    check("copy text: command succeeds", r.returncode == 0, r.stderr)
    got = wait_for(lambda: h.stub_log("clip.bin") == nonce, timeout=5)
    check("copy text: clipboard bytes match", bool(got), repr(h.stub_log("clip.bin")))
    check("copy text: kind is text", h.stub_log("clip.kind") == "text")

    png = os.path.join(h.remote_tmp, "t.png")
    # Only the magic bytes matter to the sniffer; the rest is arbitrary.
    h.ssh(rf"printf '\211PNG\r\n\032\n' > {png}; head -c 4000 /dev/urandom >> {png}")
    r = h.back(f"copy {png}")
    check("copy image: command succeeds", r.returncode == 0, r.stderr)
    got = wait_for(lambda: h.stub_log("clip.kind") == "image/png", timeout=5)
    check("copy image: sniffed as image/png", bool(got), h.stub_log("clip.kind"))
    remote_sha = h.ssh(
        f"python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],\"rb\").read()).hexdigest())' {png}"
    ).stdout.strip()
    local_sha = hashlib.sha256(
        open(os.path.join(h.logs, "clip.bin"), "rb").read()
    ).hexdigest()
    check("copy image: bytes identical", remote_sha == local_sha)


def opened_paths(h):
    """Local paths the opener stub has been handed so far."""
    return [line.strip() for line in h.stub_log("opener.log").splitlines()]


def test_transfer(h, name, size, expect_pull):
    label = f"open {name} ({size >> 10} KiB, {'pull' if expect_pull else 'inline'})"
    print(f"\n{label}:")
    remote = os.path.join(h.remote_tmp, name)
    h.ssh(f"head -c {size} /dev/urandom > {remote}")
    remote_sha = h.ssh(
        f"python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],\"rb\").read()).hexdigest())' {remote}"
    ).stdout.strip()
    seen = len(opened_paths(h))
    r = h.back(f"open {remote}", timeout=120)
    check("command succeeds", r.returncode == 0, r.stderr)
    got = wait_for(lambda: len(opened_paths(h)) > seen, timeout=15)
    if not check("local opener invoked", bool(got), h.stub_log("opener.log")):
        return
    local = opened_paths(h)[-1]
    check(
        "transferred bytes identical",
        os.path.exists(local) and sha256(local) == remote_sha,
        local,
    )
    if expect_pull:
        check(
            "went over scp (daemon log: pulled + opened)",
            f"pulled + opened {name}" in h.daemon_log(),
            h.daemon_log()[-500:],
        )
    else:
        check(
            "stayed inline (no pull in daemon log)",
            f"pull open" not in h.daemon_log(),
        )


def test_proxy(h):
    print("\nproxy:")
    port = random.randrange(20000, 40000)
    token = f"token-{random.randrange(1 << 48):x}"
    docroot = os.path.join(h.remote_tmp, "www")
    h.ssh(f"mkdir -p {docroot} && printf %s '{token}' > {docroot}/token.txt")
    r = h.ssh(
        f"cd {docroot} && nohup python3 -m http.server {port} --bind 127.0.0.1 "
        f">/dev/null 2>&1 & echo $!"
    )
    h.http_pid = r.stdout.strip() or None
    up = wait_for(
        lambda: h.ssh(
            f"python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", {port}), 1)'"
        ).returncode
        == 0,
        timeout=10,
        interval=0.3,
    )
    if not check("remote http server up", bool(up)):
        return

    url = f"http://localhost:{port}/token.txt"
    r = h.back(f"open --proxy {url}")
    check("open --proxy succeeds", r.returncode == 0, r.stderr + r.stdout)
    check("reports the tunnel", "tunneled to" in r.stdout, r.stdout)

    # The regression of 2026-08-08: under ControlMaster/ControlPersist the
    # tunnel ssh handed its forwarding to a shared mux master and exited,
    # so the tunnel worked but list/stop/reuse saw nothing.
    r = h.back("proxy list")
    listed = re.search(rf"localhost:(\d+) -> \S+:{port} \(ssh pid (\d+)\)", r.stdout)
    if not check("proxy list shows the tunnel", bool(listed), r.stdout + r.stderr):
        return
    local_port, ssh_pid = int(listed.group(1)), int(listed.group(2))

    ps = subprocess.run(
        ["ps", "-p", str(ssh_pid), "-o", "command="], capture_output=True, text=True
    ).stdout
    check(
        "tunnel ssh is alive and mux-free (ControlPath=none)",
        "ControlPath=none" in ps and f"-L {local_port}:" in ps,
        f"pid {ssh_pid}: {ps.strip() or 'gone'}",
    )

    def fetch():
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{local_port}/token.txt", timeout=3
            ) as resp:
                return resp.read().decode()
        except OSError:
            return None

    body = wait_for(fetch, timeout=10, interval=0.3)
    check("content flows through the tunnel", body == token, repr(body))

    r = h.back(f"open --proxy {url}")
    check("second open succeeds", r.returncode == 0, r.stderr + r.stdout)
    r = h.back("proxy list")
    check(
        "second open reused the tunnel (same port, still exactly one)",
        re.findall(r"localhost:(\d+) ->", r.stdout) == [str(local_port)],
        r.stdout,
    )

    r = h.back(f"proxy stop {local_port}")
    check("proxy stop succeeds", r.returncode == 0, r.stderr + r.stdout)

    def freed():
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", local_port))
            return False
        except OSError:
            return True
        finally:
            s.close()

    check("local port freed", bool(wait_for(freed, timeout=10, interval=0.3)))
    r = h.back("proxy list")
    check("proxy list empty again", "no active tunnels" in r.stdout, r.stdout)


def test_code(h):
    print("\ncode:")
    f = os.path.join(h.remote_tmp, "hello.rs")
    h.ssh(f"touch {f}")
    r = h.back(f"code -g {f}:12:3")
    check("code --goto succeeds", r.returncode == 0, r.stderr)
    got = wait_for(lambda: f"{f}:12:3" in h.stub_log("code.log"), timeout=10)
    log = h.stub_log("code.log")
    check("local code CLI got --goto path:12:3", bool(got), log)
    check("remote authority present", "ssh-remote+" in log, log)

    t0 = time.monotonic()
    r = h.back(f"code --wait {f}", timeout=60)
    elapsed = time.monotonic() - t0
    check(
        "code --wait blocks until the editor closes, then exits 0",
        r.returncode == 0 and elapsed >= 0.9,
        f"exit {r.returncode} after {elapsed:.2f}s: {r.stderr}",
    )

    # EDITOR/git contract: nonzero when the editor fails, reason visible.
    bad = os.path.join(h.remote_tmp, "fail-me.rs")
    h.ssh(f"touch {bad}")
    r = h.back(f"code --wait {bad}", timeout=60)
    check(
        "code --wait surfaces editor failure (nonzero exit, status in message)",
        r.returncode not in (0, None) and "exit status: 7" in r.stderr,
        f"exit {r.returncode}: {r.stderr}",
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("host", help="ssh destination with `back` deployed")
    ap.add_argument("--binary", default="target/debug/back", help="local back binary")
    ap.add_argument("--keep", action="store_true", help="keep the temp work dir")
    ap.add_argument("--skip-version-check", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.binary):
        fatal(f"{args.binary} not found — run `cargo build` first")

    h = Harness(args.host, args.binary, args.keep)
    try:
        print(f"setup (work dir {h.tmp}):")
        h.start_daemon()
        h.start_master()
        h.find_remote_back()
        h.check_versions(args.skip_version_check)
        h.remote_tmp = h.ssh("mktemp -d").stdout.strip()
        if not h.remote_tmp:
            fatal("could not create a remote temp dir")

        sane = h.back("status")
        check(
            "remote sees the hermetic daemon",
            "reaches a backchannel daemon" in sane.stdout,
            sane.stdout + sane.stderr,
        )

        test_copy(h)
        test_transfer(h, "small.bin", 100 * 1024, expect_pull=False)
        test_transfer(h, "big.bin", 8 * 1024 * 1024, expect_pull=True)
        test_proxy(h)
        test_code(h)
    finally:
        h.cleanup()

    passed = sum(1 for _, ok, _ in CHECKS if ok)
    print(f"\n{passed}/{len(CHECKS)} checks passed")
    sys.exit(0 if passed == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
