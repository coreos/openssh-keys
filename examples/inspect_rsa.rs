extern crate openssh_keys;

use std::{env, fs, io, path};
use std::io::BufRead;

fn main() {
    let home = env::home_dir().unwrap_or_else(|| path::PathBuf::from("/home/core/"));
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
