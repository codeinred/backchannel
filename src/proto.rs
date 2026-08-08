//! ssh-agent wire protocol: u32 big-endian length-prefixed frames, first
//! byte is the message type. We implement just enough to (a) relay frames
//! verbatim to a real agent and (b) speak our own protocol as agent
//! extensions (SSH_AGENTC_EXTENSION), so any real agent client that reaches
//! us still gets spec-conformant behavior.

use std::io::{self, Read, Write};

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_EXTENSION: u8 = 27;
pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;

pub const EXT_PING: &str = "ping@vs-connect";
pub const EXT_OPEN: &str = "open@vs-connect";
pub const EXT_SHUTDOWN: &str = "shutdown@vs-connect";

/// Far above any legitimate agent message; bounds memory against a
/// misbehaving peer.
const MAX_FRAME: u32 = 1 << 20;

pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len);
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {len} out of range"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

pub fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "truncated agent message")
}

pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub fn offset(&self) -> usize {
        self.pos
    }

    pub fn u32(&mut self) -> io::Result<u32> {
        if self.pos + 4 > self.buf.len() {
            return Err(truncated());
        }
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub fn str(&mut self) -> io::Result<String> {
        let n = self.u32()? as usize;
        if self.pos + n > self.buf.len() {
            return Err(truncated());
        }
        let s = String::from_utf8_lossy(&self.buf[self.pos..self.pos + n]).into_owned();
        self.pos += n;
        Ok(s)
    }
}

/// Build an SSH_AGENTC_EXTENSION message.
pub fn extension(name: &str, data: &[u8]) -> Vec<u8> {
    let mut m = vec![SSH_AGENTC_EXTENSION];
    put_str(&mut m, name);
    m.extend_from_slice(data);
    m
}

/// Some((name, data)) when the message is an extension request.
pub fn parse_extension(msg: &[u8]) -> Option<(String, &[u8])> {
    if msg.first() != Some(&SSH_AGENTC_EXTENSION) {
        return None;
    }
    let mut c = Cursor::new(&msg[1..]);
    let name = c.str().ok()?;
    let data = &msg[1 + c.offset()..];
    Some((name, data))
}

pub fn success_frame() -> Vec<u8> {
    vec![SSH_AGENT_SUCCESS]
}

pub fn failure_frame() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

/// Extension failure carrying a human-readable reason (our own convention;
/// stock clients just see the failure byte).
pub fn extension_failure(reason: &str) -> Vec<u8> {
    let mut m = vec![SSH_AGENT_EXTENSION_FAILURE];
    put_str(&mut m, reason);
    m
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Folder,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Folder => "folder",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "file" => Some(Kind::File),
            "folder" => Some(Kind::Folder),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowMode {
    Default,
    New,
    Reuse,
}

impl WindowMode {
    pub fn as_str(self) -> &'static str {
        match self {
            WindowMode::Default => "default",
            WindowMode::New => "new",
            WindowMode::Reuse => "reuse",
        }
    }

    pub fn parse(s: &str) -> Option<WindowMode> {
        match s {
            "default" => Some(WindowMode::Default),
            "new" => Some(WindowMode::New),
            "reuse" => Some(WindowMode::Reuse),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// line/col are 1-based; 0 means "not specified".
    Open {
        kind: Kind,
        path: String,
        line: u32,
        col: u32,
    },
    Diff { left: String, right: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    pub action: Action,
    pub window: WindowMode,
    /// Defer the final reply until the editor is closed (`code --wait`).
    /// Wait replies are two-phase: an ack frame once the CLI is spawned,
    /// then the final success/failure when it exits.
    pub wait: bool,
    /// Hostname of the sending machine — the alias fallback when the daemon
    /// can't identify the ssh process that carried the request.
    pub hostname: String,
}

impl OpenRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_u32(&mut b, 3); // protocol version
        put_str(&mut b, self.window.as_str());
        put_u32(&mut b, self.wait as u32);
        match &self.action {
            Action::Open { kind, path, line, col } => {
                put_str(&mut b, "open");
                put_str(&mut b, kind.as_str());
                put_str(&mut b, path);
                put_u32(&mut b, *line);
                put_u32(&mut b, *col);
            }
            Action::Diff { left, right } => {
                put_str(&mut b, "diff");
                put_str(&mut b, left);
                put_str(&mut b, right);
            }
        }
        put_str(&mut b, &self.hostname);
        b
    }

    pub fn decode(data: &[u8]) -> io::Result<OpenRequest> {
        let bad = |msg: String| io::Error::new(io::ErrorKind::InvalidData, msg);
        let mut c = Cursor::new(data);
        match c.u32()? {
            // v1: kind, path, hostname (pre-0.2 remotes)
            1 => {
                let kind = c.str()?;
                let kind =
                    Kind::parse(&kind).ok_or_else(|| bad(format!("bad kind {kind:?}")))?;
                Ok(OpenRequest {
                    action: Action::Open {
                        kind,
                        path: c.str()?,
                        line: 0,
                        col: 0,
                    },
                    window: WindowMode::Default,
                    wait: false,
                    hostname: c.str()?,
                })
            }
            v @ (2 | 3) => {
                let window = c.str()?;
                let window = WindowMode::parse(&window)
                    .ok_or_else(|| bad(format!("bad window mode {window:?}")))?;
                let wait = if v >= 3 { c.u32()? != 0 } else { false };
                let tag = c.str()?;
                let action = match tag.as_str() {
                    "open" => {
                        let kind = c.str()?;
                        let kind = Kind::parse(&kind)
                            .ok_or_else(|| bad(format!("bad kind {kind:?}")))?;
                        Action::Open {
                            kind,
                            path: c.str()?,
                            line: c.u32()?,
                            col: c.u32()?,
                        }
                    }
                    "diff" => Action::Diff {
                        left: c.str()?,
                        right: c.str()?,
                    },
                    other => return Err(bad(format!("bad action {other:?}"))),
                };
                Ok(OpenRequest {
                    action,
                    window,
                    wait,
                    hostname: c.str()?,
                })
            }
            v => Err(bad(format!("unsupported open@vs-connect version {v}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PingReply {
    pub version: String,
    pub pid: u32,
    pub upstream: String,
}

impl PingReply {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![SSH_AGENT_SUCCESS];
        put_str(&mut b, "vs-connect");
        put_str(&mut b, &self.version);
        put_u32(&mut b, self.pid);
        put_str(&mut b, &self.upstream);
        b
    }

    /// None when the frame isn't from a vs-connect daemon (e.g. a real
    /// ssh-agent answering SSH_AGENT_FAILURE to the unknown extension).
    pub fn decode(frame: &[u8]) -> Option<PingReply> {
        if frame.first() != Some(&SSH_AGENT_SUCCESS) {
            return None;
        }
        let mut c = Cursor::new(&frame[1..]);
        if c.str().ok()? != "vs-connect" {
            return None;
        }
        Some(PingReply {
            version: c.str().ok()?,
            pid: c.u32().ok()?,
            upstream: c.str().ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        let mut r = io::Cursor::new(buf);
        assert_eq!(read_frame(&mut r).unwrap(), b"hello");
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        let mut r = io::Cursor::new(buf);
        assert!(read_frame(&mut r).is_err());
    }

    #[test]
    fn extension_roundtrip() {
        let msg = extension(EXT_OPEN, b"payload");
        let (name, data) = parse_extension(&msg).unwrap();
        assert_eq!(name, EXT_OPEN);
        assert_eq!(data, b"payload");
    }

    #[test]
    fn non_extension_is_not_parsed() {
        assert!(parse_extension(&[SSH_AGENT_SUCCESS]).is_none());
    }

    #[test]
    fn open_request_roundtrip() {
        let req = OpenRequest {
            action: Action::Open {
                kind: Kind::Folder,
                path: "/opt/pages/vtz".into(),
                line: 0,
                col: 0,
            },
            window: WindowMode::Default,
            wait: false,
            hostname: "test-host.example.com".into(),
        };
        assert_eq!(OpenRequest::decode(&req.encode()).unwrap(), req);
    }

    #[test]
    fn goto_and_diff_roundtrip() {
        let req = OpenRequest {
            action: Action::Open {
                kind: Kind::File,
                path: "/a/b.rs".into(),
                line: 100,
                col: 5,
            },
            window: WindowMode::New,
            wait: true,
            hostname: "h".into(),
        };
        assert_eq!(OpenRequest::decode(&req.encode()).unwrap(), req);

        let req = OpenRequest {
            action: Action::Diff {
                left: "/a".into(),
                right: "/b".into(),
            },
            window: WindowMode::Reuse,
            wait: false,
            hostname: "h".into(),
        };
        assert_eq!(OpenRequest::decode(&req.encode()).unwrap(), req);
    }

    #[test]
    fn decodes_v1_requests() {
        // A 0.1.x remote: version 1, kind/path/hostname only.
        let mut b = Vec::new();
        put_u32(&mut b, 1);
        put_str(&mut b, "file");
        put_str(&mut b, "/etc/hosts");
        put_str(&mut b, "old-host");
        let req = OpenRequest::decode(&b).unwrap();
        assert_eq!(
            req.action,
            Action::Open {
                kind: Kind::File,
                path: "/etc/hosts".into(),
                line: 0,
                col: 0
            }
        );
        assert_eq!(req.window, WindowMode::Default);
    }

    #[test]
    fn ping_reply_roundtrip() {
        let reply = PingReply {
            version: "0.1.0".into(),
            pid: 4242,
            upstream: "/tmp/agent".into(),
        };
        let decoded = PingReply::decode(&reply.encode()).unwrap();
        assert_eq!(decoded.version, "0.1.0");
        assert_eq!(decoded.pid, 4242);
        assert_eq!(decoded.upstream, "/tmp/agent");
    }

    #[test]
    fn ping_reply_rejects_real_agent_failure() {
        assert!(PingReply::decode(&[SSH_AGENT_FAILURE]).is_none());
    }
}
