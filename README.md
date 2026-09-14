# git-remote-sealed

This is a git remote helper that encrypts the entire repository with [age](https://github.com/filosottile/age) in the remote host, while allowing the local clone decrypted.

Your repository stays normal on your machine. The remote (the "vault")
only ever stores encrypted files. The host (GitHub, or any other git server) cannot see the files in the repository, file names, branch names, or history.

## Getting Started

Install the helper, and then add a remote with the `sealed::` prefix. Pushing to the remote will be handled by git-remote-sealed, and commits will be stored encrypted.

```shell
# install the helper
cargo install --git https://github.com/hibariya/git-remote-sealed

# generate age key pair
age-keygen -o ~/.config/sealed-key.txt

cd my-secret-repo
git config sealed.identity ~/.config/sealed-key.txt
git remote add origin sealed::git@github.com:me/my-secret-repo.git
git push -u origin main
```

The first push creates the vault, encrypted to this device's key. The
vault itself records which keys can read it; there is nothing else to
configure. Add a recovery key next (see below) — key loss is unrecoverable.

## Platforms

Linux and macOS only for now.

Prebuilt binaries cover Linux (x86_64, aarch64) and Apple Silicon. On an
Intel Mac, build from source with `cargo install` below.

## Data Can be Recovered the Original Git History without this Tool

The encrypted files are ordinary Git bundle files with some metadata. Even without this tool, you can decrypt the files and extract the repository history with `git` and `age` and your secret keys.

```shell
age -d -i key.txt 1-full.bundle.age > full.bundle
git clone --bare full.bundle recovered.git
```

The full recovery steps are in [docs/FORMAT.md](docs/FORMAT.md), Appendix A.

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

Alternatively, build it yourself:

```shell
cargo install --git https://github.com/hibariya/git-remote-sealed
```

## Adding a device or a recovery key

The set of keys a vault is encrypted to lives inside the vault, in its
encrypted manifest. To add one, run this on any device that can already
read the vault, with the new key's PUBLIC half:

```shell
git-remote-sealed enroll age1...
```

`enroll` rewrites the vault as one snapshot encrypted to the new set, so
the added key reads the whole history from its first clone. Every other
device learns the new set on its next fetch; nothing is configured
anywhere else. Encrypt to at least two keys if the vault matters, one of
them an offline recovery key you keep somewhere else.

To add a device: generate a key there (`age-keygen`), enroll its public
half here, then clone there. Keys never move between devices, and
`git-remote-sealed info` on either side shows what is recorded.

To remove a key, `git-remote-sealed revoke age1...` compacts the vault
without it. Removal is not erasure: the host may keep earlier
generations, which that key could still read.

## More commands

- `git-remote-sealed info` — the identity, what this repository remembers about the vault, and the recipients the vault records (this device marked).
- `git-remote-sealed enroll <age1...>` — add a recipient and compact, so the whole history becomes readable by it.
- `git-remote-sealed revoke <age1...>` — remove a recipient and compact (`--yes` to remove this device's own key).
- `git-remote-sealed upgrade` — record the recipient set in a vault written by 0.2.x (see below).
- `git-remote-sealed compact` — rewrites the vault as one snapshot.  Deleted history really disappears from the host here.
- `git-remote-sealed forget --yes` — discard this repository's memory of a vault you deliberately re-created. Read its warning first.

## Upgrading from 0.2.x

Vaults written by 0.2.x do not record their recipients. Run this once
per vault, from any device that can read it:

```shell
git-remote-sealed upgrade
```

Reads (clone, fetch) work without it; a push to a not-yet-upgraded vault
is refused and tells you to run it. The recorded set is this device's
identity plus its `sealed.recipients`, and it must match the number of
keys the vault is already encrypted to. A mismatch is refused with both
counts, so a stale global entry cannot be sealed in by accident.
Afterwards remove `sealed.recipients` everywhere (`git config
--show-origin --get-all sealed.recipients`): a key it names that the
vault does not have is refused on write; use `enroll` instead.

A vault written by 0.3.0 still reads on 0.2.x, but 0.2.x refuses to push
to it, as the format requires for manifest lines it does not know.
Upgrade each device before it pushes again. See [CHANGELOG.md](CHANGELOG.md).

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
