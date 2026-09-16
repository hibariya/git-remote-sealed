# git-remote-sealed

A git remote helper that encrypts your whole repository with [age](https://github.com/filosottile/age) before it reaches the remote.

Your repository stays normal on your machine. The remote (the "vault")
stores only encrypted files. The host (GitHub, or any other git server)
cannot see file contents, file names, branch names, or history.

## Getting started

Install the helper (see [Installation](#installation)), make a key, and
add a remote with the `sealed::` prefix. Git hands every push and fetch
to the helper.

```shell
# make a key pair for this device
age-keygen -o ~/.config/sealed-key.txt

cd my-secret-repo
git config sealed.identity ~/.config/sealed-key.txt
git remote add origin sealed::git@github.com:me/my-secret-repo.git
git push -u origin main
```

The first push creates the vault, encrypted to this device's key only.
The vault itself remembers which keys can read it. There is nothing else
to configure.

Next, add a recovery key. If you lose every key, the data is gone.

```shell
age-keygen -o recovery-key.txt        # keep this file somewhere safe, offline
git-remote-sealed enroll age1...      # its PUBLIC half, printed by age-keygen
```

## Adding a device

Keys never move between devices. Each device makes its own key, and a
device that already reads the vault lets the new one in.

1. On the new device: `age-keygen -o ~/.config/sealed-key.txt`. Copy the
   public half (the `age1...` line).
2. On a device that already reads the vault:
   `git-remote-sealed enroll age1...`
3. On the new device: set `sealed.identity`, then `git clone sealed::...`.

`enroll` rewrites the vault so the new key can read the whole history.
Every other device picks up the new key list on its next fetch.

To remove a key: `git-remote-sealed revoke age1...`. Removal is not
erasure. The host may still keep older copies that the removed key can
read.

## Commands

- `git-remote-sealed info` — this device's key, what it remembers about the vault, and the keys the vault is encrypted to.
- `git-remote-sealed enroll <age1...>` — add a key.
- `git-remote-sealed revoke <age1...>` — remove a key (`--yes` to remove this device's own key).
- `git-remote-sealed compact` — rewrite the vault as one snapshot. Deleted history really leaves the host here. `--repair` also fixes a vault whose recorded keys do not match what it is encrypted to.
- `git-remote-sealed upgrade` — for vaults made with 0.2.x (see below).
- `git-remote-sealed forget --yes` — forget what this repository knows about a vault you re-created on purpose. Read its warning first.

## Upgrading from 0.2.x

Vaults made with 0.2.x do not record their keys. Run this once per
vault, from any device that can read it:

```shell
git-remote-sealed upgrade
```

Until then, reads work but pushes are refused with a message that says
to run it. The recorded keys are this device's key plus the old
`sealed.recipients` setting, and their number must match how many keys
the vault is already encrypted to. If it does not, the upgrade is
refused and prints both numbers. If a key is gone for good (a lost
device), `upgrade --yes` records the smaller set and locks that key
out. After the upgrade, delete `sealed.recipients` from your git
config; `enroll` replaces it.

Do it in this order: upgrade every old vault first, then delete the
setting, then create new vaults. A leftover `sealed.recipients` in your
global git config blocks the first push to a new vault, because a new
vault starts with this device's key only.

0.2.x can still read a vault written by 0.3.0, but cannot push to it.
Upgrade each device before it pushes again. See
[CHANGELOG.md](CHANGELOG.md).

## Platforms

Linux and macOS only for now.

Prebuilt binaries cover Linux (x86_64, aarch64) and Apple Silicon. On an
Intel Mac, build from source with `cargo install` below.

## Installation

You need `git` and `age-keygen` on PATH.

Download a build from the [releases page](https://github.com/hibariya/git-remote-sealed/releases), check it, and put it on your PATH:

```shell
# proves the archive was built by this repo's release workflow, from a
# known commit — a checksum only says it matches a list published beside it
gh attestation verify git-remote-sealed-<target>.tar.gz --repo hibariya/git-remote-sealed

shasum -a 256 -c SHA256SUMS --ignore-missing
tar xzf git-remote-sealed-<target>.tar.gz
install -m 0755 git-remote-sealed-<target>/git-remote-sealed ~/.local/bin/
```

The Linux builds are static, so they do not care how old the distribution is.

Or build it yourself:

```shell
cargo install --git https://github.com/hibariya/git-remote-sealed
```

## Recovery without this tool

The encrypted files are ordinary git bundles. With `git`, `age`, and
your secret key, you can get the history back without this helper:

```shell
age -d -i key.txt 1-full.bundle.age > full.bundle
git clone --bare full.bundle recovered.git
```

The full recovery steps are in [docs/FORMAT.md](docs/FORMAT.md), Appendix A.

## The format and protocol

Start with [How a sealed vault works](docs/OVERVIEW.md) for a short explanation
of the files, push, fetch, and compaction.

[docs/FORMAT.md](docs/FORMAT.md) specifies the on-remote format completely enough to build another implementation from, with no reference to this code. It carries its own threat model (§1, §10) and a disaster-recovery appendix.

For the protocol core (sequence allocation, the trust-on-first-use pin, compaction) the machine-checked Quint model in [spec/](spec/) is normative: where the prose and the model disagree, the model wins. See [spec/README.md](spec/README.md) for what is proved, at what bounds, and what is deliberately left to simulation.

[Design notes](docs/DESIGN-NOTES.md) explain why the individual rules exist.

## Contributing

This implementation is written **from the spec alone**. If you port a fix from another implementation, say so in the pull request — where two implementations disagree, that is either a spec bug or an implementation bug, and quietly copying one into the other turns it into shared folklore instead.

Run the tests the way CI does, without a host toolchain:

```shell
podman compose run --rm check      # fmt, clippy, and every test
```

To verify the Quint specs, run:

```shell
podman compose run --rm spec # fast lane
podman compose run --rm spec-full # absence proofs (40min .. hours)
```

## Future works

- Post-quantum key support
- Support more platforms

## License

[MIT](LICENSE)
