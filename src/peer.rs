//! Identify the process on the other end of a unix-socket connection. The
//! daemon uses this to (a) reject other users outright and (b) read the ssh
//! client's argv to learn which host alias a request arrived through.

use std::io;
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone, Copy)]
pub struct PeerInfo {
    pub pid: i32,
    pub uid: u32,
}

#[cfg(target_os = "macos")]
pub fn peer_info(stream: &UnixStream) -> io::Result<PeerInfo> {
    use std::os::fd::AsRawFd;

    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERCRED: libc::c_int = 0x001;
    const LOCAL_PEERPID: libc::c_int = 0x002;

    // Matches struct xucred from <sys/ucred.h> (XU_NGROUPS = 16).
    #[repr(C)]
    struct XUCred {
        cr_version: libc::c_uint,
        cr_uid: libc::uid_t,
        cr_ngroups: libc::c_short,
        cr_groups: [libc::gid_t; 16],
    }

    let fd = stream.as_raw_fd();

    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut cred: XUCred = unsafe { std::mem::zeroed() };
    let mut clen = std::mem::size_of::<XUCred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut clen,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(PeerInfo {
        pid: pid as i32,
        uid: cred.cr_uid,
    })
}

#[cfg(target_os = "macos")]
pub fn process_argv(pid: i32) -> Option<Vec<String>> {
    // sysctl KERN_PROCARGS2 layout: i32 argc, then the exec path
    // (NUL-terminated, NUL-padded), then argc NUL-terminated argv strings,
    // then the environment (which we ignore). Only works for same-uid
    // processes, which is all we need.
    const KERN_PROCARGS2: libc::c_int = 49;

    let mib = [libc::CTL_KERN, KERN_PROCARGS2, pid as libc::c_int];
    let mut size: libc::size_t = 0;
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut libc::c_int,
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }

    let mut buf = vec![0u8; size + 1024]; // slack: args can grow between calls
    let mut size = buf.len() as libc::size_t;
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut libc::c_int,
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(size);

    if buf.len() < 4 {
        return None;
    }
    let argc = i32::from_ne_bytes(buf[0..4].try_into().ok()?).max(0) as usize;
    let mut pos = 4;
    while pos < buf.len() && buf[pos] != 0 {
        pos += 1; // exec path
    }
    while pos < buf.len() && buf[pos] == 0 {
        pos += 1; // padding
    }

    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        let start = pos;
        while pos < buf.len() && buf[pos] != 0 {
            pos += 1;
        }
        if pos > buf.len() {
            break;
        }
        args.push(String::from_utf8_lossy(&buf[start..pos]).into_owned());
        pos += 1;
    }
    if args.is_empty() { None } else { Some(args) }
}

#[cfg(target_os = "linux")]
pub fn peer_info(stream: &UnixStream) -> io::Result<PeerInfo> {
    use std::os::fd::AsRawFd;

    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerInfo {
        pid: cred.pid,
        uid: cred.uid,
    })
}

#[cfg(target_os = "linux")]
pub fn process_argv(pid: i32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let mut args: Vec<String> = raw
        .split(|b| *b == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    while args.last().is_some_and(|s| s.is_empty()) {
        args.pop();
    }
    if args.is_empty() { None } else { Some(args) }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn peer_info(_stream: &UnixStream) -> io::Result<PeerInfo> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credentials not implemented on this platform",
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn process_argv(_pid: i32) -> Option<Vec<String>> {
    None
}
