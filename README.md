# openssh-keys

[![crates.io](https://img.shields.io/crates/v/openssh-keys.svg)](https://crates.io/crates/openssh-keys)
[![Documentation](https://docs.rs/openssh-keys/badge.svg)](https://docs.rs/openssh-keys)

A pure-Rust library to handle OpenSSH public keys.

`openssh-keys` can parse, print, and fingerprint OpenSSH public keys.
It supports the following algorithms:

* RSA
* DSA
* ECDSA (nistp256, nistp384, nistp521)
* ED25519

It can construct RSA and DSA keys from their components using the `PublicKey::from_rsa()` and
`PublicKey::from_dsa()` functions respectively.

## Example

```rust
extern crate openssh_keys;

use std::{env, fs, io, path};
use std::io::BufRead;

fn main() {
    let home = env::home_dir().unwrap_or(path::PathBuf::from("/home/core/"));
    let pub_path = home.join(".ssh").join("id_rsa.pub");
    println!("Inspecting '{}':", pub_path.to_string_lossy());
    let file = fs::File::open(&pub_path).expect("unable to open RSA pubkey");
    let reader = io::BufReader::new(file);
    
    for (i, line) in reader.lines().enumerate() {
        let line = line.expect(&format!("unable to read key at line {}", i + 1));
        let pubkey = openssh_keys::PublicKey::parse(&line).expect("unable to parse RSA pubkey");
        println!(" * Pubkey #{} -> {}", i + 1, pubkey.to_fingerprint_string());
    }
}
```

Some more examples are available under [examples](examples).

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
