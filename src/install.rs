//! `back install-as-code`: create the `code` shim — a symlink named `code`
//! pointing at the `back` binary — and report whether it wins `code` lookup
//! on this shell's PATH.
//!
//! Shadowing every other `code` is safe by design: the shim defers to VS
//! Code's own CLI in integrated terminals and execs the machine's real
//! `code` when run outside an ssh session (open.rs), so first-on-PATH is
//! always the right place for it. The failure mode worth diagnosing is the
//! shim sitting *behind* a system VS Code (/usr/bin/code,
//! /opt/homebrew/bin/code) — hence the resolution report and the `--at`
//! suggestion pointing at an earlier user-writable directory.
//!
//! The diagnosis can only see the PATH of the shell it runs in; interactive
//! and `ssh host cmd` shells often differ. The messages say "this shell"
//! deliberately.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub fn run(at: Option<PathBuf>, check: bool, force: bool) -> Result<()> {
    let self_exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("cannot resolve the running `back` binary")?;
    let home = std::env::var_os("HOME").map(PathBuf::from);

    let mut installed = None;
    if !check {
        let dir = match at {
            Some(d) => expand_tilde(&d, home.as_deref()),
            None => self_exe
                .parent()
                .expect("a canonicalized binary path has a parent")
                .to_path_buf(),
        };
        let shim = install_shim(&dir, &self_exe, force)?;
        println!("installed: {} -> {}", shim.display(), self_exe.display());
        installed = Some(shim);
    }

    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let diag = diagnose(&path_var, home.as_deref(), &self_exe);
    report(&diag, installed.as_deref());

    if check && !diag.entries.first().is_some_and(|e| e.is_shim) {
        bail!("`code` does not resolve to a backchannel shim in this shell");
    }
    Ok(())
}

struct Entry {
    path: PathBuf,
    is_shim: bool,
}

struct Diagnosis {
    /// Every executable `code` on PATH, in lookup order.
    entries: Vec<Entry>,
    /// A better `--at` target: user-writable, on PATH ahead of the winner.
    suggestion: Option<PathBuf>,
}

fn diagnose(path_var: &OsStr, home: Option<&Path>, self_exe: &Path) -> Diagnosis {
    let dirs: Vec<PathBuf> = std::env::split_paths(path_var)
        .filter(|d| !d.as_os_str().is_empty())
        .collect();
    let entries: Vec<Entry> = dirs
        .iter()
        .map(|d| d.join("code"))
        .filter(|c| is_executable_file(c))
        .map(|c| Entry { is_shim: is_shim(&c, self_exe), path: c })
        .collect();

    let suggestion = match entries.first() {
        Some(e) if e.is_shim => None,
        winner => {
            // Only directories strictly ahead of the winning `code` help; a
            // dir ahead of it can't itself contain one (it would have won).
            let winner_dir = winner.and_then(|e| e.path.parent());
            dirs.iter()
                .take_while(|d| winner_dir.is_none_or(|w| d.as_path() != w))
                .find(|d| is_suggestable(d, home))
                .cloned()
        }
    };
    Diagnosis { entries, suggestion }
}

fn report(diag: &Diagnosis, installed: Option<&Path>) {
    match diag.entries.first() {
        None => {
            match installed {
                Some(shim) => eprintln!(
                    "warning: {} is not on this shell's PATH — `code` won't find the shim",
                    shim.parent().unwrap_or(shim).display()
                ),
                None => eprintln!("warning: no `code` found on this shell's PATH"),
            }
            suggest(diag);
        }
        Some(first) if first.is_shim => {
            println!(
                "`code` in this shell resolves to the shim: {}",
                first.path.display()
            );
            if let Some(real) = diag.entries.iter().find(|e| !e.is_shim) {
                println!(
                    "  ({} stays reachable — the shim runs it when you're outside an ssh session)",
                    real.path.display()
                );
            }
        }
        Some(winner) => {
            eprintln!(
                "warning: `code` in this shell resolves to {}, not the backchannel shim",
                winner.path.display()
            );
            if diag.entries.len() > 1 {
                eprintln!("  every `code` on this shell's PATH, in order:");
                for e in &diag.entries {
                    let tag = if e.is_shim { "  (backchannel shim)" } else { "" };
                    eprintln!("    {}{tag}", e.path.display());
                }
            } else if let Some(shim) = installed {
                eprintln!(
                    "  the shim at {} is not on this shell's PATH",
                    shim.display()
                );
            }
            suggest(diag);
        }
    }
}

fn suggest(diag: &Diagnosis) {
    match &diag.suggestion {
        Some(d) => eprintln!(
            "  {} comes earlier on PATH and is user-writable — try:\n    back install-as-code --at {}",
            d.display(),
            d.display()
        ),
        None => eprintln!(
            "  no user-writable directory comes earlier on PATH — put the shim's directory \
             ahead in PATH instead (in ~/.zshenv or ~/.bashrc, so non-interactive ssh \
             commands see it too)"
        ),
    }
}

/// Create (or refresh) the `code` symlink in `dir`, pointing at `self_exe`.
fn install_shim(dir: &Path, self_exe: &Path, force: bool) -> Result<PathBuf> {
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let shim = dir.join("code");

    if let Ok(meta) = fs::symlink_metadata(&shim) {
        // A dangling symlink is a leftover from an uninstalled binary; safe
        // to replace. Anything else that isn't ours needs --force.
        let dangling = meta.is_symlink() && fs::metadata(&shim).is_err();
        if !is_shim(&shim, self_exe) && !dangling && !force {
            bail!(
                "{} already exists and is not a backchannel shim — pass --force to replace it",
                shim.display()
            );
        }
    }

    // Link-then-rename so an existing `code` is never briefly missing.
    let tmp = dir.join(format!(".code.tmp.{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    std::os::unix::fs::symlink(self_exe, &tmp)
        .with_context(|| format!("cannot create a symlink in {}", dir.display()))?;
    if let Err(e) = fs::rename(&tmp, &shim) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("cannot replace {}", shim.display()));
    }
    Ok(shim)
}

/// Same spirit as open.rs's shim check, but here an unresolvable candidate
/// is "not the shim" (find_local_code treats it as unlaunchable instead).
fn is_shim(candidate: &Path, self_exe: &Path) -> bool {
    candidate.canonicalize().is_ok_and(|c| {
        c == self_exe || c.file_name().is_some_and(|n| n == "back" || n == "backchannel")
    })
}

fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // metadata() follows symlinks, so a dangling `code` link is skipped —
    // matching how a shell's PATH search would pass over it.
    fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Worth suggesting via --at: absolute, under $HOME (so we never point users
/// at system directories), and either writable or absent-but-creatable.
fn is_suggestable(d: &Path, home: Option<&Path>) -> bool {
    let Some(home) = home else { return false };
    if !d.is_absolute() || !d.starts_with(home) || d == home {
        return false;
    }
    match fs::metadata(d) {
        Ok(m) => m.is_dir() && writable(d),
        // On PATH but missing — install_shim will create it.
        Err(_) => true,
    }
}

fn writable(d: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(d.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

/// `--at '~/bin'` arrives literally when quoted; expand a leading `~` so it
/// still means what the user meant. (`~user` forms are not handled.)
fn expand_tilde(d: &Path, home: Option<&Path>) -> PathBuf {
    match (home, d.strip_prefix("~")) {
        (Some(home), Ok(rest)) => home.join(rest),
        _ => d.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    /// Unique per-test sandbox with a fake $HOME and a fake `back` binary.
    struct Sandbox {
        base: PathBuf,
    }

    impl Sandbox {
        fn new(name: &str) -> Sandbox {
            let base =
                std::env::temp_dir().join(format!("bc-install-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).unwrap();
            let sb = Sandbox { base };
            fs::create_dir_all(sb.home()).unwrap();
            let back = sb.home().join("back");
            write_exec(&back);
            sb
        }

        fn home(&self) -> PathBuf {
            self.base.join("home")
        }

        /// The fake `back` binary, canonicalized as run() would see it.
        fn self_exe(&self) -> PathBuf {
            self.home().join("back").canonicalize().unwrap()
        }

        fn dir(&self, name: &str) -> PathBuf {
            let d = self.base.join(name);
            fs::create_dir_all(&d).unwrap();
            d
        }

        fn home_dir(&self, name: &str) -> PathBuf {
            let d = self.home().join(name);
            fs::create_dir_all(&d).unwrap();
            d
        }

        fn with_real_code(&self, name: &str) -> PathBuf {
            let d = self.dir(name);
            write_exec(&d.join("code"));
            d
        }

        fn with_shim(&self, name: &str) -> PathBuf {
            let d = self.dir(name);
            symlink(self.self_exe(), d.join("code")).unwrap();
            d
        }

        fn diagnose(&self, dirs: &[&Path]) -> Diagnosis {
            let path_var = std::env::join_paths(dirs).unwrap();
            // $HOME and PATH stay as-spelled (no canonicalize), mirroring
            // run(): starts_with(home) compares them textually.
            diagnose(&path_var, Some(&self.home()), &self.self_exe())
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn write_exec(path: &Path) {
        fs::write(path, "#!/bin/sh\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn shim_first_wins() {
        let sb = Sandbox::new("shim-first");
        let shim = sb.with_shim("shimdir");
        let sys = sb.with_real_code("sysdir");
        let d = sb.diagnose(&[&shim, &sys]);
        assert_eq!(d.entries.len(), 2);
        assert!(d.entries[0].is_shim);
        assert!(!d.entries[1].is_shim);
        assert!(d.suggestion.is_none());
    }

    #[test]
    fn shadowed_shim_suggests_earlier_home_dir() {
        let sb = Sandbox::new("suggest");
        let early = sb.home_dir("local-bin"); // under $HOME, ahead of the winner
        let sys = sb.with_real_code("sysdir");
        let shim = sb.with_shim("shimdir");
        let d = sb.diagnose(&[&early, &sys, &shim]);
        assert!(!d.entries[0].is_shim);
        assert!(d.entries[1].is_shim);
        assert_eq!(d.suggestion.as_deref(), Some(early.as_path()));
    }

    #[test]
    fn no_suggestion_without_earlier_home_dir() {
        let sb = Sandbox::new("no-suggest");
        let sys = sb.with_real_code("sysdir");
        let shim = sb.with_shim("shimdir");
        let outside = sb.dir("outside-home"); // ahead, but not under $HOME
        let d = sb.diagnose(&[&outside, &sys, &shim]);
        assert!(!d.entries[0].is_shim);
        assert!(d.suggestion.is_none());
    }

    #[test]
    fn missing_home_dir_on_path_is_suggested() {
        let sb = Sandbox::new("missing-dir");
        let sys = sb.with_real_code("sysdir");
        let ghost = sb.home().join("not-created-yet");
        let d = sb.diagnose(&[&ghost, &sys]);
        assert_eq!(d.suggestion.as_deref(), Some(ghost.as_path()));
    }

    #[test]
    fn dangling_code_symlink_is_skipped() {
        let sb = Sandbox::new("dangling");
        let broken = sb.dir("brokendir");
        symlink(sb.base.join("gone"), broken.join("code")).unwrap();
        let sys = sb.with_real_code("sysdir");
        let d = sb.diagnose(&[&broken, &sys]);
        assert_eq!(d.entries.len(), 1);
        assert_eq!(d.entries[0].path, sys.join("code"));
    }

    #[test]
    fn non_executable_code_is_ignored() {
        let sb = Sandbox::new("noexec");
        let plain = sb.dir("plaindir");
        fs::write(plain.join("code"), "not a program").unwrap();
        let d = sb.diagnose(&[&plain]);
        assert!(d.entries.is_empty());
    }

    #[test]
    fn install_creates_and_refreshes() {
        let sb = Sandbox::new("install");
        let dir = sb.base.join("bin"); // does not exist yet: created on demand
        let shim = install_shim(&dir, &sb.self_exe(), false).unwrap();
        assert_eq!(fs::read_link(&shim).unwrap(), sb.self_exe());
        // Re-running over our own shim is fine without --force.
        install_shim(&dir, &sb.self_exe(), false).unwrap();
        assert_eq!(fs::read_link(&shim).unwrap(), sb.self_exe());
    }

    #[test]
    fn install_replaces_dangling_link_without_force() {
        let sb = Sandbox::new("relink");
        let dir = sb.dir("bin");
        symlink(sb.base.join("gone"), dir.join("code")).unwrap();
        install_shim(&dir, &sb.self_exe(), false).unwrap();
        assert_eq!(fs::read_link(dir.join("code")).unwrap(), sb.self_exe());
    }

    #[test]
    fn install_refuses_foreign_code_unless_forced() {
        let sb = Sandbox::new("force");
        let dir = sb.dir("bin");
        write_exec(&dir.join("code"));
        let err = install_shim(&dir, &sb.self_exe(), false).unwrap_err();
        assert!(err.to_string().contains("--force"), "got: {err}");
        install_shim(&dir, &sb.self_exe(), true).unwrap();
        assert_eq!(fs::read_link(dir.join("code")).unwrap(), sb.self_exe());
    }

    #[test]
    fn tilde_expansion() {
        let home = Path::new("/home/u");
        assert_eq!(
            expand_tilde(Path::new("~/bin"), Some(home)),
            Path::new("/home/u/bin")
        );
        assert_eq!(
            expand_tilde(Path::new("/abs/bin"), Some(home)),
            Path::new("/abs/bin")
        );
        assert_eq!(expand_tilde(Path::new("~/bin"), None), Path::new("~/bin"));
    }
}
