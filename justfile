default:
    @just --list

build:
    cargo build

test:
    cargo test

# copy source to <host>, cargo-install it there, and (re)link the `code` shim
deploy-dev host:
    ssh {{host}} 'mkdir -p .vs-connect/src'
    rsync -az --delete --exclude /target --exclude /.git --exclude /logs ./ {{host}}:.vs-connect/src/
    ssh {{host}} 'PATH="$HOME/.cargo/bin:$PATH" cargo install --path .vs-connect/src && ln -sf vs-connect "${CARGO_HOME:-$HOME/.cargo}/bin/code"'
