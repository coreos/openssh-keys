# Release notes

## Upcoming openssh-keys 0.6.3 (unreleased)

Changes:

 - Require Rust ≥ 1.75.0

## openssh-keys 0.6.2 (2023-06-27)

Changes:

- Require `md-5` 0.10, `sha2` 0.10 to avoid mismatched Rust Crypto dependencies


## openssh-keys 0.6.1 (2023-06-01)

Changes:

- Require Rust ≥ 1.58.0
- Require `base64` ≥ 0.21
- Switch example code from `dirs` dependency to `home`
- Add release notes doc


## openssh-keys 0.6.0 (2022-11-18)

Changes:

- cargo: allow md-5 and sha2 0.10
- cargo: explicitly set `sign-tag` 
- dependabot: switch to weekly cadence
- git: rename `master` branch to `main`
- github/ISSUE_TEMPLATE: add release checklist
- lib: Support Hardware Security Keys
- templates: release process updates
- workflows: bump MSRV and lint toolchain


## openssh-keys 0.5.0 (2021-03-16)

- API change: Switch error-handling library from `error-chain` to `thiserror`
- Update to Rust 2018
- Fix build warnings with newer Rust
- Update `base64` to 0.13
- Exclude tooling configuration from packaged crate


## openssh-keys 0.4.2 (2020-06-22)

Changes:

- cargo: update all dependencies
- cargo: update manifest and rustfmt whole project
- dependabot: create config file
- travis: update minimum and clippy toolchains


## openssh-keys 0.4.1 (2018-11-01)

Changes:

- Update base64 requirement from 0.9 to 0.10


## openssh-keys 0.4.0 (2018-10-24)

Changes:

- lib: clean all clippy warnings
- cargo: update all dependencies to latest
- travis: add minimum toolchain and clippy passes
- remove appveyor ci
- move repo under the coreos org on github


## openssh-keys 0.3.0 (2018-07-11)

Changes:

- update `error-chain` from `0.11.x` to `0.12.x`
- update `base64` from `0.8.x` to `0.9.x`


## openssh-keys 0.2.2 (2017-12-14)

Changes:

- Make `PublicKey` fields public (#14, thanks @Trolldemorted!)
- bump `base64` from `0.6.x` to `0.8.x`
- bump `sha2` from `0.6.x` to `0.7.x`


## openssh-keys 0.2.1 (2017-12-05)

Changes:

- add md5 fingerprinting with `fingerprint_md5` and `to_fingerprint_md5_string`
- move fingerprint algorithm label to `to_fingerprint_string` and `to_fingerprint_md5_string`, now `fingerprint` only prints the fingerprint without the hashing algorithm label


## openssh-keys 0.2.0 (2017-11-07)

Changes:

- respect authorized_keys file options and known_hosts hostnames (#7). this means that `read_keys` is now a valid `authorized_keys` file and `known_hosts` file parser.


## openssh-keys 0.1.2 (2017-11-07)

Changes:

- cleaned up release crate
- added several trait derivations for exported datatypes
- renamed `to_key_file` to `to_key_format`
- added `read_keys` which reads multiple newline separated keys from a `Read`. it would be a fully featured authorized_keys file and known_hosts file parser except for #7. 


## openssh-keys 0.1.1 (2017-09-20)

Changes:

- bumps `error-chain` to `v0.11.0`
- uses `sha2` library instead of `rust-crypto` for `sha256` fingerprint hashes
- adds docs and examples


## openssh-keys 0.1.0 (2017-09-01)

`ssh-keys` can parse, write, and fingerprint all ssh public keys supported by `ssh-keygen` at the time of writing that can be used for public/private key authentication (eg not certs and sign-only keys). 
