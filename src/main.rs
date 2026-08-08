mod clipboard;
mod copy;
mod daemon;
mod launch;
mod logging;
mod open;
mod paths;
mod peer;
mod progress;
mod proto;
mod proxy;
mod ssh_argv;
mod status;

use anyhow::Result;
use clap::{Parser, Subcommand};

// Keep the about line in step with Cargo.toml `description` and the README
// intro; revisit the wording together once the README gets its editorial pass.
#[derive(Parser)]
#[command(
    name = "back",
    version,
    about = "Open projects and files on the host machine from within an ssh session, \
             tunneled over agent forwarding"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the local daemon that ssh forwards to remotes as "the agent"
    Daemon {
        /// Replace a running daemon instead of exiting
        #[arg(long)]
        replace: bool,
        /// Stay in the foreground and echo the log to stderr
        #[arg(long)]
        foreground: bool,
    },
    /// From a remote ssh session: open paths in VS Code on your local machine
    /// (what the `code` shim runs)
    Code {
        /// Force a new window
        #[arg(short = 'n', long, conflicts_with = "reuse_window")]
        new_window: bool,
        /// Reuse the last active window
        #[arg(short = 'r', long)]
        reuse_window: bool,
        /// Treat args as path:line[:col] even if a file with the literal
        /// (colon-containing) name exists
        #[arg(short = 'g', long = "goto")]
        goto: bool,
        /// Compare two files
        #[arg(short = 'd', long, num_args = 2, value_names = ["LEFT", "RIGHT"])]
        diff: Option<Vec<String>>,
        /// Block until the editor is closed (single path or --diff)
        #[arg(short = 'w', long)]
        wait: bool,
        /// Files or folders to open; positions as path:line[:col] jump there
        #[arg(required_unless_present = "diff")]
        paths: Vec<String>,
    },
    /// Like the platform `open`, but backwards across ssh: URLs open in
    /// your local browser, files transfer and open with your local default app
    Open {
        /// Tunnel a remote loopback URL here (ssh -L) before opening it
        #[arg(long)]
        proxy: bool,
        /// http(s) URLs or files
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Copy a file (or stdin) to the clipboard — on your local machine when
    /// run over ssh. Detects text vs image (png/jpeg/gif/tiff) content.
    Copy {
        /// File to copy; omit to read from stdin
        file: Option<String>,
    },
    /// Inspect or stop the daemon's ssh -L tunnels
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },
    /// Report what backchannel can see from here (daemon, sockets, forwarding)
    Status,
}

#[derive(Subcommand)]
enum ProxyAction {
    /// List active tunnels
    List,
    /// Stop a tunnel by its local port, or all of them
    Stop {
        /// Local port of the tunnel to stop
        port: Option<u16>,
        /// Stop every tunnel
        #[arg(long)]
        all: bool,
    },
}

fn main() -> Result<()> {
    // Installed as a `code` shim (symlink named "code"), we take raw args as
    // paths and skip clap so `code .` feels exactly like the real thing.
    let mut raw: Vec<String> = std::env::args().collect();
    let argv0 = std::path::Path::new(&raw[0])
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if argv0 == "code" {
        return open::run_as_code_shim(raw.split_off(1));
    }

    match Cli::parse().command {
        Command::Daemon { replace, foreground } => daemon::run(replace, foreground),
        Command::Code { new_window, reuse_window, goto, diff, wait, paths } => {
            open::run(open::OpenOptions {
                window: if new_window {
                    proto::WindowMode::New
                } else if reuse_window {
                    proto::WindowMode::Reuse
                } else {
                    proto::WindowMode::Default
                },
                force_goto: goto,
                diff: diff.map(|mut v| {
                    let right = v.pop().expect("clap enforces two values");
                    let left = v.pop().expect("clap enforces two values");
                    (left, right)
                }),
                wait,
                paths,
            })
        }
        Command::Open { proxy, targets } => open::run_open(targets, proxy),
        Command::Copy { file } => copy::run(file),
        Command::Proxy { action } => match action {
            ProxyAction::List => proxy::list(),
            ProxyAction::Stop { port, all } => proxy::stop(port, all),
        },
        Command::Status => status::run(),
    }
}
