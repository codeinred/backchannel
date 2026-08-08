//! Recover the ssh destination ("test-host", "user@host") from an ssh client's
//! argv. This is how the daemon learns which host alias a request came from:
//! the process connecting to our socket is the ssh client carrying that
//! session, and its command line names the destination the user typed —
//! which is exactly the authority VS Code needs for vscode-remote://.

/// ssh options that consume a following argument (from `man ssh` usage).
const OPTS_WITH_ARG: &[char] = &[
    'B', 'b', 'c', 'D', 'E', 'e', 'F', 'I', 'i', 'J', 'L', 'l', 'm', 'O', 'o', 'P', 'p', 'R',
    'S', 'W', 'w',
];

pub fn destination(argv: &[String]) -> Option<String> {
    let prog = argv.first()?;
    // ControlPersist masters rewrite their title ("ssh: /path/ctl [mux]");
    // no destination is recoverable there — callers fall back to the
    // hostname carried in the request payload.
    if prog.contains("[mux]") {
        return None;
    }
    let name = std::path::Path::new(prog).file_name()?.to_str()?;
    if !name.contains("ssh") {
        return None;
    }

    let mut i = 1;
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "--" {
            return clean(argv.get(i + 1)?);
        }
        if let Some(flags) = arg.strip_prefix('-') {
            if flags.is_empty() {
                return None; // bare "-" is not ssh usage we understand
            }
            // Flags cluster ("-4Ap2222"); the first option that takes an
            // argument consumes the rest of the token, or the next token.
            let mut chars = flags.chars();
            let mut consumes_next = false;
            while let Some(c) = chars.next() {
                if OPTS_WITH_ARG.contains(&c) {
                    consumes_next = chars.as_str().is_empty();
                    break;
                }
            }
            i += if consumes_next { 2 } else { 1 };
        } else {
            return clean(&argv[i]);
        }
    }
    None
}

/// The control-socket path from a ControlPersist background master's
/// rewritten title ("ssh: /path/to/socket [mux]"). The alias isn't in the
/// title, but the daemon can map paths to aliases it has seen before.
pub fn mux_control_path(argv: &[String]) -> Option<String> {
    let joined = argv.join(" ");
    let rest = joined.strip_prefix("ssh: ")?;
    let (path, _) = rest.split_once(" [mux]")?;
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

fn clean(dest: &str) -> Option<String> {
    let d = dest.strip_prefix("ssh://").unwrap_or(dest);
    let d = d.split('/').next().unwrap_or(d);
    if d.is_empty() {
        None
    } else {
        Some(d.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn plain() {
        assert_eq!(destination(&argv(&["ssh", "test-host"])).unwrap(), "test-host");
    }

    #[test]
    fn absolute_path_and_user() {
        assert_eq!(
            destination(&argv(&["/usr/bin/ssh", "-p", "2222", "user@host", "uptime"])).unwrap(),
            "user@host"
        );
    }

    #[test]
    fn options_with_arguments() {
        assert_eq!(
            destination(&argv(&["ssh", "-o", "ForwardAgent=yes", "-J", "jump", "test-host"])).unwrap(),
            "test-host"
        );
    }

    #[test]
    fn clustered_flags_with_inline_arg() {
        assert_eq!(destination(&argv(&["ssh", "-4Ap2222", "host"])).unwrap(), "host");
    }

    #[test]
    fn clustered_flags_with_separate_arg() {
        assert_eq!(
            destination(&argv(&["ssh", "-4Ap", "2222", "host"])).unwrap(),
            "host"
        );
    }

    #[test]
    fn double_dash() {
        assert_eq!(destination(&argv(&["ssh", "--", "host"])).unwrap(), "host");
    }

    #[test]
    fn uri_form() {
        assert_eq!(
            destination(&argv(&["ssh", "ssh://user@h:2222/"])).unwrap(),
            "user@h:2222"
        );
    }

    #[test]
    fn mux_master_is_inconclusive() {
        assert!(destination(&argv(&["ssh: /tmp/ctl [mux]"])).is_none());
    }

    #[test]
    fn mux_title_yields_control_path() {
        assert_eq!(
            mux_control_path(&argv(&["ssh: /Users/x/.ssh/cm-4dd8bb65 [mux]"])).unwrap(),
            "/Users/x/.ssh/cm-4dd8bb65"
        );
        // macOS argv parsing may split the title on spaces
        assert_eq!(
            mux_control_path(&argv(&["ssh:", "/Users/x/.ssh/cm-abc", "[mux]"])).unwrap(),
            "/Users/x/.ssh/cm-abc"
        );
        assert!(mux_control_path(&argv(&["ssh", "test-host"])).is_none());
        assert!(mux_control_path(&argv(&["ssh: "])).is_none());
    }

    #[test]
    fn non_ssh_process_is_inconclusive() {
        assert!(destination(&argv(&["backchannel", "open", "."])).is_none());
    }

    #[test]
    fn flag_only_argv_is_inconclusive() {
        assert!(destination(&argv(&["ssh", "-v"])).is_none());
    }
}
