# backchannel: talk back to your host

`back` is a tool that allows you to open files and interface with a host machine
from within an ssh session. The goal is to make host-remote communication fast,
convenient, and seamless on remotes you trust.

```sh
# spawn vscode remote session on the host, and open ./vtz
back code ./vtz

# Open a file specific line/column
back code src/main.cpp:127:32

# copy files back to the host, and open with default program
back open vtz/flamegraph.svg

# open in the browser on host
back open https://example.com

# forward port 8080 on the host to the remote, and then open
# on the host browser
back open --proxy http://localhost:8080

# Run a command, and copy the output to the host clipboard
fd '\.h' | back copy

# Copy on image into the host clipboard, from the remote
back copy vtz/images/raw_benchmarks.png
```

`back` builds on top of ForwardAgent's protocol extension mechanism to tunnel
data through the authentication socket. Only `back`-related commands and queries
are handled by `back`; everything else is forwarded to the system's ssh agent,
so authentication and key signing continue to work as normal.

[ForwardAgent] ensures that each ssh session gets a fresh socket on the remote,
so `back` can automatically track which remote requests come from, multiple
sessions just work, and sockets are cleaned up automatically.

On the remote `back` can automatically discover the appropriate channel via
`$SSH_AUTH_SOCK`, so no per-host configuration is required.

[ForwardAgent]:
  https://docs.github.com/en/authentication/connecting-to-github-with-ssh/using-ssh-agent-forwarding

<details>
<summary><bold>What is <code>ForwardAgent</code>?</bold></summary>

[ForwardAgent] is a mechanism by which you can allow remote sessions to
authenticate access with the keys on your local machine.

Let's say you're developing on a remote machine over ssh, and you want to push
or pull from git.

You _could_ create an ssh key on the machine, register it with github, and then
use that. But this is cumbersome: if you need to create a separate key for every
single remote, you end up registering a ton of keys with github (and all the
other services which communicate via ssh).

You could alternatively copy your private key to the remote machine, but this
creates additional risk - if the remote machine is compromised, your private key
could be exfiltrated, and this problem gets worse as you have more remote
machines.

`ForwardAgent` provides a solution: authentication requests that occur on the
remote are _forwarded_ to the ssh agent on your local machine, which signs them
with the private key you've stored locally.

**The key itself is not copied.** All authentication still happens locally, so
this is much _more_ secure than copying the key to the remote machine.

**Caveats:** If the remote machine is compromised, a malicious actor can send
authentication requests via `ForwardAgent`, and use them to pose as you on
places such as github. But - importantly - this only works _while the ssh
session is active_. Once you disconnect, they lose the ability to authenticate
requests posing as you. This makes `ForwardAgent` a lot safer, since they have
no way to permanently steal your private key.

That being said: only enable `ForwardAgent` with _hosts that you trust._

</details>

## Installation & Setup

**Setup - host machine:** Install `back` with cargo, spawn the daemon with
`back daemon`, and configure `ForwardAgent` to use `~/.backchannel/agent.sock`
for the desired hosts.

```sh
cargo install backchannel
```

Add the following to your `.zshrc` or `.bashrc`:

```sh
# If `back` is found on the PATH, spawn a daemon on the host.
# Exits silently if an existing daemon is already running
command -v back > /dev/null && back daemon
```

Finally, configure `ForwardAgent` to communicate with the daemon via
`~/.ssh/config`:

```
Host dev-machine-1 dev-machine-2 dev-machine-3
    ForwardAgent ~/.backchannel/agent.sock
```

**Setup - remote machine:** Install `back` with cargo:

```sh
cargo install backchannel
```

sshd on the remote machine must allow agent forwarding
(`AllowAgentForwarding yes`), but it's already enabled by default for most
machines.
