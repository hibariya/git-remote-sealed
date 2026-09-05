# Quint + Apalache toolchain for the sealed v2 formal model.
# Context is the repo root (see compose.yaml), same convention as sealed-tools.
# Trixie, not bookworm: quint's prebuilt Rust evaluator needs glibc >= 2.39.
FROM docker.io/library/node:24-trixie

RUN apt-get update \
 && apt-get install -y --no-install-recommends openjdk-21-jre-headless \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @informalsystems/quint

# Warm both engines into the image so runs need no network: `verify` pulls
# the Apalache distribution, `test` pulls the Rust evaluator. Both warmups
# must SUCCEED — a silent download failure here would resurface as a
# confusing runtime error later.
COPY spec/warm.qnt /tmp/warm.qnt
RUN quint verify --max-steps=1 --invariant=inv /tmp/warm.qnt
RUN quint test /tmp/warm.qnt
