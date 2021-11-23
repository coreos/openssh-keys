# Release process

This project uses [cargo-release][cargo-release] in order to prepare new releases, tag and sign the relevant git commit, and publish the resulting artifacts to [crates.io][crates-io].
The release process follows the usual PR-and-review flow, allowing an external reviewer to have a final check before publishing.

## Requirements

This guide requires:

 * A web browser (and network connectivity)
 * `git`
 * [GPG setup][GPG setup] and personal key for signing
 * `cargo` (suggested: latest stable toolchain from [rustup][rustup])
 * `cargo-release` (suggested: `cargo install -f cargo-release`)
 * A verified account on crates.io
 * Write access to this GitHub project
 * Membership in the [Fedora CoreOS Crates Owners group](https://github.com/orgs/coreos/teams/fedora-coreos-crates-owners/members), which will give you upload access to crates.io

## Release checklist

These steps show how to release version `x.y.z` on the `origin` remote (this can be checked via `git remote -av`).
Push access to the upstream repository is required in order to publish the new tag and the PR branch.

:warning:: if `origin` is not the name of the locally configured remote that points to the upstream git repository (i.e. `git@github.com:coreos/openssh-keys.git`), be sure to assign the correct remote name to the `UPSTREAM_REMOTE` variable.

- make sure the project is clean and prepare the environment:
  - [ ] Make sure `cargo-release` is up to date: `cargo install cargo-release`
  - [ ] `cargo test --all-features`
  - [ ] `cargo clean`
  - [ ] `git clean -fd`
  - [ ] `RELEASE_VER=x.y.z`
  - [ ] `UPSTREAM_REMOTE=origin`

- create release commits on a dedicated branch and tag it (the commits and tag will be signed with the GPG signing key you configured):
  - [ ] `git checkout -b release-${RELEASE_VER}`
  - [ ] `cargo release --execute ${RELEASE_VER}` (and confirm the version when prompted)

- open and merge a PR for this release:
  - [ ] `git push ${UPSTREAM_REMOTE} release-${RELEASE_VER}`
  - [ ] open a web browser and create a PR for the branch above
  - [ ] make sure the resulting PR contains exactly one commit
  - [ ] in the PR body, write a short changelog with relevant changes since last release
  - [ ] get the PR reviewed, approved and merged

- publish the artifacts (tag and crate):
  - [ ] `git checkout v${RELEASE_VER}`
  - [ ] verify that `grep "^version = \"${RELEASE_VER}\"$" Cargo.toml` produces output
  - [ ] `git push ${UPSTREAM_REMOTE} v${RELEASE_VER}`
  - [ ] `cargo publish`

- publish the release:
  - [ ] find the new tag in the [GitHub tag list](https://github.com/coreos/openssh-keys/tags), click the triple dots menu, and create a release for it
  - [ ] write a short changelog (i.e. re-use the PR content)
  - [ ] publish release

- clean up the local environment (optional, but recommended):
  - [ ] `cargo clean`
  - [ ] `git checkout main`
  - [ ] `git pull ${UPSTREAM_REMOTE} main`
  - [ ] `git push ${UPSTREAM_REMOTE} :release-${RELEASE_VER}`
  - [ ] `git branch -d release-${RELEASE_VER}`

[cargo-release]: https://github.com/sunng87/cargo-release
[rustup]: https://rustup.rs/
[crates-io]: https://crates.io/
[GPG setup]: https://docs.github.com/en/github/authenticating-to-github/managing-commit-signature-verification
