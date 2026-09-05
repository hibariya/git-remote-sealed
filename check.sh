#!/bin/sh
# The gate, run inside the container (compose service `check`):
# formatting, lints as errors, and every test including the e2e smoke.
set -eux
cd /repo

cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
