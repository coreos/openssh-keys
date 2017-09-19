# ssh-keys &emsp; [![Travis Status]][travis] [![AppVeyor Status]][appveyor] [![Latest Version]][crates.io] [![Docs Badge]][docs]

[Travis Status]: https://api.travis-ci.org/sdemos/ssh-keys.svg?branch=master
[travis]: https://travis-ci.org/sdemos/ssh-keys
[AppVeyor Status]: https://ci.appveyor.com/api/projects/status/jxobgtenuy72e544?svg=true
[appveyor]: https://ci.appveyor.com/project/sdemos/ssh-keys
[Latest Version]: https://img.shields.io/crates/v/openssh-keys.svg
[crates.io]: https://crates.io/crates/openssh-keys
[Docs Badge]: https://docs.rs/openssh-keys/badge.svg
[docs]: https://docs.rs/openssh-keys

`ssh-keys` can parse, print, and fingerprint OpenSSH public keys in pure rust.

`ssh-keys` supports the following algorithms:

* RSA
* DSA
* ECDSA (nistp256, nistp384, nistp521)
* ED25519

It can construct RSA and DSA keys from their components using the `from_rsa` and
`from_dsa` functions respectively.

At some point in the future, this crate may add support for private ssh keys as
well.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
