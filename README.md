# git-remote-sealed

This is a git remote helper that encrypts the entire repository with [age](https://github.com/filosottile/age) in the remote host, while allowing the local clone decrypted.

Your repository stays normal on your machine. The remote (the "vault")
only ever stores encrypted files. The host (GitHub, or any other git server) cannot see the files in the repository, file names, branch names, or history.

## Getting Started

Install the helper, and then add a remote with the `sealed::` prefix. Pushing to the remote will be handled by git-remote-sealed, and commits will be stored encrypted.

```shell
# install the helper
cargo install --git https://github.com/hibariya/git-remote-sealed

cd my-secret-repo
git remote add origin sealed::git@github.com:you/my-secret-repo.git
git push -u origin main
```

## Your data does not depend on this tool

If this project disappears, you can still restore everything with only
`git` and `age`:

```
age -d -i key.txt 1-full.bundle.age > full.bundle
git clone --bare full.bundle recovered.git
```

The full recovery steps are in
[docs/FORMAT.md](docs/FORMAT.md), Appendix A.
The test suite runs that recipe verbatim, with the stock binaries, so it
cannot quietly stop working.

## Install

You need `git` on PATH. Encryption is built in — no `age` binary needed.
Linux and macOS only (see the release workflow for why).

Download a build from the [releases
page](https://github.com/hibariya/git-remote-sealed/releases), check it,
and put it on your PATH:

```
shasum -a 256 -c SHA256SUMS --ignore-missing
tar xzf git-remote-sealed-<target>.tar.gz
install -m 0755 git-remote-sealed-<target>/git-remote-sealed ~/.local/bin/
```

The Linux builds are static, so they do not care how old the distribution
is. Or build it yourself:

```
cargo install --git https://github.com/hibariya/git-remote-sealed
```

## Set up

```
age-keygen -o key.txt        # keep this file safe: losing it loses the vault
git config sealed.identity /path/to/key.txt
```

Make an empty repo on your host, then use it with the `sealed::` prefix:

```
git clone sealed::git@github.com:you/my-vault.git notes
```

Push, pull, and clone work as usual after that.

Encrypt to more than one key if the vault matters — one of them an
offline recovery key you keep somewhere else:

```
git config --add sealed.recipients age1...   # the other key's PUBLIC half
```

`sealed.recipients` is multi-valued and git merges every config scope, so
set it per repository and check what is actually in force:

```
git config --show-origin --get-all sealed.recipients
```

## More commands

- `git-remote-sealed info` — shows your vault setup, and the steps to
  add a new device (keys never move between devices).
- `git-remote-sealed compact` — rewrites the vault as one snapshot.
  Deleted history really disappears from the host here.

## The format

[docs/FORMAT.md](docs/FORMAT.md) specifies the
on-remote format completely enough to build another implementation from,
with no reference to this code. It carries its own threat model (§1, §10)
and a disaster-recovery appendix.

For the protocol core — sequence allocation, the trust-on-first-use pin,
compaction — the machine-checked model in [spec/](spec/) is
normative: where the prose and the model disagree, the model wins. See
[spec/README.md](spec/README.md) for what is proved, at what bounds,
and what is deliberately left to simulation.

## Contributing

This implementation is written **from the spec alone**. If you port a fix
from another implementation, say so in the pull request — where two
implementations disagree, that is either a spec bug or an implementation
bug, and quietly copying one into the other turns it into shared folklore
instead.

Run the tests the way CI does, without a host toolchain:

```
podman compose run --rm check      # fmt, clippy, and every test
```

## License

[MIT](LICENSE)
