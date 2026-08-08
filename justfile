default:
    @just --list

build:
    cargo build

test:
    cargo test

# copy source to <host>, cargo-install it there, and (re)link the `code` shim
deploy-dev host:
    ssh {{host}} 'mkdir -p .backchannel/src'
    rsync -az --delete --exclude /target --exclude /.git --exclude /logs ./ {{host}}:.backchannel/src/
    ssh {{host}} 'PATH="$HOME/.cargo/bin:$PATH" cargo install --path .backchannel/src && ln -sf back "${CARGO_HOME:-$HOME/.cargo}/bin/code"'
