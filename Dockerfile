# Toolchain image for this crate (see compose.yaml). The crate is mounted,
# not copied; this image only carries rust + git.
FROM docker.io/library/rust:1.94-slim-bookworm

# git: the helper shells out to real git for bundles (FORMAT.md's design —
# there is no git library dependency), and the e2e tests need it too.
# age (the CLI): NOT used by the helper (it embeds the age crate) — it is
# what tests/claims_e2e.rs runs FORMAT.md's Appendix A recipe with, so the
# "recoverable with stock git + age" claim is exercised with the stock
# binaries themselves.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git age ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The slim image ships the minimal rustup profile; the gate needs both.
RUN rustup component add clippy rustfmt
