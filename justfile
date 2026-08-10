default:
    @just --list

build:
    cargo build

test:
    cargo test

# end-to-end against a real host over real ssh (hermetic daemon, stubbed
# side effects). Needs `back` deployed there first: just deploy-dev <host>
live-test host: build
    python3 tests/live.py {{host}}

# copy source to <host>, cargo-install it there, and (re)link the `code` shim
deploy-dev host:
    ssh {{host}} 'mkdir -p .backchannel/src'
    rsync -az --delete --exclude /target --exclude /.git --exclude /logs ./ {{host}}:.backchannel/src/
    ssh {{host}} 'PATH="$HOME/.cargo/bin:$PATH" cargo install --path .backchannel/src && "${CARGO_HOME:-$HOME/.cargo}/bin/back" install-as-code'
