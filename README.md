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

## Platforms

Linux and macOS only for now.

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

## Additional Age Encryption Recipients

Encrypt to more than one key if the vault matters (one of them an offline recovery key you keep somewhere else):

```shell
git config --add sealed.recipients age1...   # the other key's PUBLIC half
```

`sealed.recipients` is multi-valued and git merges every config scope, so set it per repository and check what is actually in force:

```shell
git config --show-origin --get-all sealed.recipients
```

## More commands

- `git-remote-sealed info` — shows your vault setup, and the steps to add a new device (keys never move between devices).
- `git-remote-sealed compact` — rewrites the vault as one snapshot.  Deleted history really disappears from the host here.

## The format and protocol

[docs/FORMAT.md](docs/FORMAT.md) specifies the on-remote format completely enough to build another implementation from, with no reference to this code. It carries its own threat model (§1, §10) and a disaster-recovery appendix.

For the protocol core (sequence allocation, the trust-on-first-use pin, compaction) the machine-checked Quint model in [spec/](spec/) is normative: where the prose and the model disagree, the model wins. See [spec/README.md](spec/README.md) for what is proved, at what bounds, and what is deliberately left to simulation.

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
