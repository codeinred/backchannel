mod daemon;
mod launch;
mod logging;
mod open;
mod paths;
mod peer;
mod proto;
mod ssh_argv;
mod status;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "vs-connect",
    version,
    about = "Open VS Code windows on your local machine from remote ssh sessions"
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
    Open {
        /// Files or folders to open
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Report what vs-connect can see from here (daemon, sockets, forwarding)
    Status,
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
        Command::Open { paths } => open::run(paths),
        Command::Status => status::run(),
    }
}
