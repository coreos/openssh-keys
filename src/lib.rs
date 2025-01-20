//! A pure-Rust library to handle OpenSSH public keys.
//!
//! This crate supports parsing, manipulation, and some basic validation of
//! SSH keys. It provides a struct for encapsulation of SSH keys in projects.
//!
//! `openssh-keys` does not have the ability to generate SSH keys. However,
//! it does allow to construct RSA and DSA keys from their components, so if you
//! generate the keys with another library (say, rust-openssl), then you can
//! output the SSH public keys with this library.
//!
//! # Example
//!
//! ```rust
//! use std::{env, fs, io, path};
//! use std::io::BufRead;
//!
//! fn inspect_rsa() {
//!     let home = env::home_dir().unwrap_or(path::PathBuf::from("/home/core/"));
//!     let pub_path = home.join(".ssh").join("id_rsa.pub");
//!     println!("Inspecting '{}':", pub_path.to_string_lossy());
//!     let file = fs::File::open(&pub_path).expect("unable to open RSA pubkey");
//!     let reader = io::BufReader::new(file);
//!
//!     for (i, line) in reader.lines().enumerate() {
//!         let line = line.expect(&format!("unable to read key at line {}", i + 1));
//!         let pubkey = openssh_keys::PublicKey::parse(&line).expect("unable to parse RSA pubkey");
//!         println!(" * Pubkey #{} -> {}", i + 1, pubkey.to_fingerprint_string());
//!     }
//! }
#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

mod reader;
mod writer;

pub mod errors {
    use thiserror::Error;

    use alloc::string::String;

    pub type Result<T> = core::result::Result<T, OpenSSHKeyError>;

    #[derive(Error, Debug)]
    pub enum OpenSSHKeyError {
        #[cfg(any(feature = "std", test, doc))]
        #[error("I/O error")]
        IO {
            #[from]
            source: std::io::Error,
        },

        #[error("invalid UTF-8")]
        InvalidUtf8 {
            #[from]
            source: core::str::Utf8Error,
        },

        // keep base64::DecodeError out of the public API
        #[error("invalid base64: {detail}")]
        InvalidBase64 { detail: String },

        #[error("invalid key format")]
        InvalidFormat,

        #[error("unsupported keytype: {keytype}")]
        UnsupportedKeyType { keytype: String },

        #[error("unsupported curve: {curve}")]
        UnsupportedCurve { curve: String },
    }
}

use crate::errors::*;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use md5::Md5;
use sha2::{Digest, Sha256};

use crate::reader::Reader;
use crate::writer::Writer;

use core::fmt;

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const SSH_RSA: &str = "ssh-rsa";
const SSH_DSA: &str = "ssh-dss";
const SSH_ED25519: &str = "ssh-ed25519";
const SSH_ED25519_SK: &str = "sk-ssh-ed25519@openssh.com";
const SSH_ECDSA_256: &str = "ecdsa-sha2-nistp256";
const SSH_ECDSA_384: &str = "ecdsa-sha2-nistp384";
const SSH_ECDSA_521: &str = "ecdsa-sha2-nistp521";
const SSH_ECDSA_SK: &str = "sk-ecdsa-sha2-nistp256@openssh.com";
const NISTP_256: &str = "nistp256";
const NISTP_384: &str = "nistp384";
const NISTP_521: &str = "nistp521";

/// Curves for ECDSA
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    Nistp256,
    Nistp384,
    Nistp521,
}

impl Curve {
    /// get converts a curve name of the type in the format described in
    /// https://tools.ietf.org/html/rfc5656#section-10 and returns a curve
    /// object.
    fn get(curve: &str) -> Result<Self> {
        Ok(match curve {
            NISTP_256 => Curve::Nistp256,
            NISTP_384 => Curve::Nistp384,
            NISTP_521 => Curve::Nistp521,
            _ => {
                return Err(OpenSSHKeyError::UnsupportedCurve {
                    curve: curve.to_string(),
                })
            }
        })
    }

    /// curvetype gets the curve name in the format described in
    /// https://tools.ietf.org/html/rfc5656#section-10
    fn curvetype(self) -> &'static str {
        match self {
            Curve::Nistp256 => NISTP_256,
            Curve::Nistp384 => NISTP_384,
            Curve::Nistp521 => NISTP_521,
        }
    }
}

impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.curvetype())
    }
}

/// Data is the representation of the data section of an ssh public key. it is
/// an enum with all the different supported key algorithms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    Rsa {
        exponent: Vec<u8>,
        modulus: Vec<u8>,
    },
    Dsa {
        p: Vec<u8>,
        q: Vec<u8>,
        g: Vec<u8>,
        pub_key: Vec<u8>,
    },
    Ed25519 {
        key: Vec<u8>,
    },
    Ed25519Sk {
        key: Vec<u8>,
        application: Vec<u8>,
    },
    Ecdsa {
        curve: Curve,
        key: Vec<u8>,
    },
    EcdsaSk {
        curve: Curve,
        key: Vec<u8>,
        application: Vec<u8>,
    },
}

/// `PublicKey` is the struct representation of an ssh public key.
#[derive(Clone, Debug, Eq)]
pub struct PublicKey {
    pub options: Option<String>,
    pub data: Data,
    pub comment: Option<String>,
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_key_format())
    }
}

/// Two public keys are equivalent if their data sections are equivalent,
/// ignoring their comment section.
impl core::cmp::PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.data == other.data
    }
}

impl core::str::FromStr for PublicKey {
    type Err = OpenSSHKeyError;
    fn from_str(s: &str) -> Result<Self> {
        PublicKey::parse(s)
    }
}

impl PublicKey {
    /// parse takes a string and parses it as a public key from an authorized
    /// keys file. the format it expects is described here
    /// https://tools.ietf.org/html/rfc4253#section-6.6 and here
    /// https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT
    ///
    /// sshd describes an additional, optional "options" field for public keys
    /// in the authorized_keys file. This field allows for passing of options to
    /// sshd that only apply to that particular public key. This means that a
    /// public key in an authorized keys file is a strict superset of the public
    /// key format described in rfc4253. Another superset of a public key is
    /// what is present in the known_hosts file. This file has a hostname as the
    /// first thing on the line. This parser treats the hostname the same as an
    /// option field. When one of these things is found at the beginning of a
    /// line, it is treated as a semi-opaque string that is carried with the
    /// public key and reproduced when the key is printed. It is not entirely
    /// opaque, since the parser needs to be aware of quoting semantics within
    /// the option fields, since options surrounded by double quotes can contain
    /// spaces, which are otherwise the main delimiter of the parts of a public
    /// key.
    ///
    /// You can parse and output ssh keys like this
    ///
    /// ```
    /// let rsa_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcMCOEryBa8IkxXacjIawaQPp08hR5h7+4vZePZ7DByTG3tqKgZYRJ86BaR+4fmdikFoQjvLJVUmwniq3wixhkP7VLCbqip3YHzxXrzxkbPC3w3O1Bdmifwn9cb8RcZXfXncCsSu+h5XCtQ5BOi41Iit3d13gIe/rfXVDURmRanV6R7Voljxdjmp/zyReuzc2/w5SI6Boi4tmcUlxAI7sFuP1kA3pABDhPtc3TDgAcPUIBoDCoY8q2egI197UuvbgsW2qraUcuQxbMvJOMSFg2FQrE2bpEqC4CtBn7+HiJrkVOHjV7bvSv7jd1SuX5XqkwMCRtdMuRpJr7CyZoFL5n demos@anduin";
    /// let key = openssh_keys::PublicKey::parse(rsa_key).unwrap();
    /// let out = key.to_string();
    /// assert_eq!(rsa_key, out);
    /// ```
    ///
    /// parse somewhat attempts to keep track of comments, but it doesn't fully
    /// comply with the rfc in that regard.
    pub fn parse(key: &str) -> Result<Self> {
        // trim leading and trailing whitespace
        let key = key.trim();
        // try just parsing the keys straight up
        PublicKey::try_key_parse(key).or_else(|e| {
            // remove the preceeding string
            let mut key_start = 0;
            let mut escape = false;
            let mut quote = false;
            let mut marker = key.starts_with('@');
            for (i, c) in key.chars().enumerate() {
                if c == '\\' {
                    escape = true;
                    continue;
                }
                if escape {
                    escape = false;
                    continue;
                }
                if c == '"' {
                    quote = !quote;
                }
                if !quote && (c == ' ' || c == '\t') {
                    if marker {
                        marker = false;
                        continue;
                    } else {
                        key_start = i + 1;
                        break;
                    }
                }
            }
            let mut parsed = PublicKey::try_key_parse(&key[key_start..]).map_err(|_| e)?;
            parsed.options = Some(key[..key_start - 1].into());
            Ok(parsed)
        })
    }

    fn try_key_parse(key: &str) -> Result<Self> {
        // then parse the key according to rfc4253
        let (keytype, remaining) = key
            .split_once(char::is_whitespace)
            .ok_or(OpenSSHKeyError::InvalidFormat)?;

        let (data, comment) = remaining
            .split_once(char::is_whitespace)
            .unwrap_or((remaining, ""));

        let comment = comment.trim();
        if comment.contains('\n') {
            return Err(OpenSSHKeyError::InvalidFormat);
        }
        let comment = if comment.is_empty() {
            None
        } else {
            Some(comment.to_owned())
        };

        let buf = BASE64
            .decode(data)
            .map_err(|e| OpenSSHKeyError::InvalidBase64 {
                detail: format!("{}", e),
            })?;
        let mut reader = Reader::new(&buf);
        let data_keytype = reader.read_string()?;
        if keytype != data_keytype {
            return Err(OpenSSHKeyError::InvalidFormat);
        }

        let data = match keytype {
            SSH_RSA => {
                // the data for an rsa key consists of three pieces:
                //    ssh-rsa public-exponent modulus
                // see ssh-rsa format in https://tools.ietf.org/html/rfc4253#section-6.6
                let e = reader.read_mpint()?;
                let n = reader.read_mpint()?;
                Data::Rsa {
                    exponent: e.into(),
                    modulus: n.into(),
                }
            }
            SSH_DSA => {
                // the data stored for a dsa key is, in order
                //    ssh-dsa p q g public-key
                // p and q are primes
                // g = h^((p-1)/q) where 1 < h < p-1
                // public-key is the value that is actually generated in
                // relation to the secret key
                // see https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
                // and ssh-dss format in https://tools.ietf.org/html/rfc4253#section-6.6
                // and https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L743
                let p = reader.read_mpint()?;
                let q = reader.read_mpint()?;
                let g = reader.read_mpint()?;
                let pub_key = reader.read_mpint()?;
                Data::Dsa {
                    p: p.into(),
                    q: q.into(),
                    g: g.into(),
                    pub_key: pub_key.into(),
                }
            }
            SSH_ED25519 => {
                // the data stored for an ed25519 is just the point on the curve
                // for now the exact specification of the point on that curve is
                // a mystery to me, instead of having to compute it, we just
                // assume the key we got is correct and copy that verbatim. this
                // also means we have to disallow arbitrary construction until
                // furthur notice.
                // see https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L772
                let key = reader.read_bytes()?;
                Data::Ed25519 { key: key.into() }
            }
            SSH_ED25519_SK => {
                // same as above
                let key = reader.read_bytes()?;
                let application = reader.read_bytes()?;
                Data::Ed25519Sk {
                    key: key.into(),
                    application: application.into(),
                }
            }
            SSH_ECDSA_256 | SSH_ECDSA_384 | SSH_ECDSA_521 => {
                // ecdsa is of the form
                //    ecdsa-sha2-[identifier] [identifier] [data]
                // the identifier is one of nistp256, nistp384, nistp521
                // the data is some weird thing described in section 2.3.4 and
                // 2.3.4 of https://www.secg.org/sec1-v2.pdf so for now we
                // aren't going to bother actually computing it and instead we
                // will just not let you construct them.
                //
                // see the data definition at
                // https://tools.ietf.org/html/rfc5656#section-3.1
                // and the openssh output
                // https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L753
                // and the openssh buffer writer implementation
                // https://github.com/openssh/openssh-portable/blob/master/sshbuf-getput-crypto.c#L192
                // and the openssl point2oct implementation
                // https://github.com/openssl/openssl/blob/aa8f3d76fcf1502586435631be16faa1bef3cdf7/crypto/ec/ec_oct.c#L82
                let curve = reader.read_string()?;
                let key = reader.read_bytes()?;
                Data::Ecdsa {
                    curve: Curve::get(curve)?,
                    key: key.into(),
                }
            }
            SSH_ECDSA_SK => {
                // same as above (like there, we don't assert that the curve matches what was specified in the keytype)
                let curve = reader.read_string()?;
                let key = reader.read_bytes()?;
                let application = reader.read_bytes()?;
                Data::EcdsaSk {
                    curve: Curve::get(curve)?,
                    key: key.into(),
                    application: application.into(),
                }
            }
            _ => {
                return Err(OpenSSHKeyError::UnsupportedKeyType {
                    keytype: keytype.to_string(),
                })
            }
        };

        Ok(PublicKey {
            options: None,
            data,
            comment,
        })
    }

    /// read_keys takes a reader and parses it as an authorized_keys file. it
    /// returns an error if it can't read or parse any of the public keys in the
    /// list.
    #[cfg(any(feature = "std", test, doc))]
    pub fn read_keys<R>(r: R) -> Result<Vec<Self>>
    where
        R: std::io::Read,
    {
        use std::io::{BufRead, BufReader};
        let keybuf = BufReader::new(r);
        // authorized_keys files are newline-separated lists of public keys
        let mut keys = Vec::new();
        for key in keybuf.lines() {
            let key = key?;
            // skip any empty lines and any comment lines (prefixed with '#')
            if !key.is_empty() && !(key.trim().starts_with('#')) {
                keys.push(PublicKey::parse(&key)?);
            }
        }
        Ok(keys)
    }

    /// get an ssh public key from rsa components
    pub fn from_rsa(e: Vec<u8>, n: Vec<u8>) -> Self {
        PublicKey {
            options: None,
            data: Data::Rsa {
                exponent: e,
                modulus: n,
            },
            comment: None,
        }
    }

    /// get an ssh public key from dsa components
    pub fn from_dsa(p: Vec<u8>, q: Vec<u8>, g: Vec<u8>, pkey: Vec<u8>) -> Self {
        PublicKey {
            options: None,
            data: Data::Dsa {
                p,
                q,
                g,
                pub_key: pkey,
            },
            comment: None,
        }
    }

    /// keytype returns the type of key in the format described by rfc4253
    /// The output will be ssh-{type} where type is [rsa,ed25519,ecdsa,dsa]
    pub fn keytype(&self) -> &'static str {
        match self.data {
            Data::Rsa { .. } => SSH_RSA,
            Data::Dsa { .. } => SSH_DSA,
            Data::Ed25519 { .. } => SSH_ED25519,
            Data::Ed25519Sk { .. } => SSH_ED25519_SK,
            Data::Ecdsa { ref curve, .. } => match *curve {
                Curve::Nistp256 => SSH_ECDSA_256,
                Curve::Nistp384 => SSH_ECDSA_384,
                Curve::Nistp521 => SSH_ECDSA_521,
            },
            Data::EcdsaSk { .. } => SSH_ECDSA_SK,
        }
    }

    /// data returns the data section of the key in the format described by rfc4253
    /// the contents of the data section depend on the keytype. For RSA keys it
    /// contains the keytype, exponent, and modulus in that order. Other types
    /// have other data sections. This function doesn't base64 encode the data,
    /// that task is left to the consumer of the output.
    pub fn data(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_string(self.keytype());
        match self.data {
            Data::Rsa {
                ref exponent,
                ref modulus,
            } => {
                // the data for an rsa key consists of three pieces:
                //    ssh-rsa public-exponent modulus
                // see ssh-rsa format in https://tools.ietf.org/html/rfc4253#section-6.6
                writer.write_mpint(exponent.clone());
                writer.write_mpint(modulus.clone());
            }
            Data::Dsa {
                ref p,
                ref q,
                ref g,
                ref pub_key,
            } => {
                writer.write_mpint(p.clone());
                writer.write_mpint(q.clone());
                writer.write_mpint(g.clone());
                writer.write_mpint(pub_key.clone());
            }
            Data::Ed25519 { ref key } => {
                writer.write_bytes(key.clone());
            }
            Data::Ed25519Sk {
                ref key,
                ref application,
            } => {
                writer.write_bytes(key.clone());
                writer.write_bytes(application.clone());
            }
            Data::Ecdsa { ref curve, ref key } => {
                writer.write_string(curve.curvetype());
                writer.write_bytes(key.clone());
            }
            Data::EcdsaSk {
                ref curve,
                ref key,
                ref application,
            } => {
                writer.write_string(curve.curvetype());
                writer.write_bytes(key.clone());
                writer.write_bytes(application.clone());
            }
        }
        writer.into_vec()
    }

    pub fn set_comment(&mut self, comment: &str) {
        self.comment = Some(comment.to_string());
    }

    /// to_key_format returns a string representation of the ssh key. this string
    /// output is appropriate to use as a public key file. it adheres to the
    /// format described in https://tools.ietf.org/html/rfc4253#section-6.6
    ///
    /// an ssh key consists of four pieces:
    ///
    ///    [options] ssh-keytype data comment
    ///
    /// the output of the data section is described in the documentation for the
    /// data function. the options section is optional, and is not part of the
    /// spec. rather, it is a field present in authorized_keys files or
    /// known_hosts files.
    pub fn to_key_format(&self) -> String {
        let key = format!(
            "{} {} {}",
            self.keytype(),
            BASE64.encode(self.data()),
            self.comment.clone().unwrap_or_default()
        );
        if let Some(ref options) = self.options {
            format!("{} {}", options, key)
        } else {
            key
        }
    }

    /// size returns the size of the stored ssh key. for rsa keys this is
    /// determined by the number of bits in the modulus. for dsa keys it's the
    /// number of bits in the prime p.
    ///
    /// see https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L261
    /// for more details
    pub fn size(&self) -> usize {
        match self.data {
            Data::Rsa { ref modulus, .. } => modulus.len() * 8,
            Data::Dsa { ref p, .. } => p.len() * 8,
            Data::Ed25519 { .. } | Data::Ed25519Sk { .. } => 256, // ??
            Data::Ecdsa { ref curve, .. } | Data::EcdsaSk { ref curve, .. } => match *curve {
                Curve::Nistp256 => 256,
                Curve::Nistp384 => 384,
                Curve::Nistp521 => 521,
            },
        }
    }

    /// fingerprint returns a string representing the fingerprint of the ssh key
    /// the format of the fingerprint is described tersely in
    /// https://tools.ietf.org/html/rfc4716#page-6. This uses the ssh-keygen
    /// defaults of a base64 encoded SHA256 hash.
    pub fn fingerprint(&self) -> String {
        let data = self.data();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hashed = hasher.finalize();
        let mut fingerprint = BASE64.encode(hashed);
        // trim padding characters off the end. I'm not clear on exactly what
        // this is doing but they do it here and the test fails without it
        // https://github.com/openssh/openssh-portable/blob/643c2ad82910691b2240551ea8b14472f60b5078/sshkey.c#L918
        if let Some(l) = fingerprint.find('=') {
            fingerprint.truncate(l);
        };
        fingerprint
    }

    /// to_fingerprint_string prints out the fingerprint in the same format used
    /// by `ssh-keygen -l -f key`, specifically the implementation here -
    /// https://github.com/openssh/openssh-portable/blob/master/ssh-keygen.c#L842
    /// right now it just sticks with the defaults of a base64 encoded SHA256
    /// hash.
    pub fn to_fingerprint_string(&self) -> String {
        let keytype = match self.data {
            Data::Rsa { .. } => "RSA",
            Data::Dsa { .. } => "DSA",
            Data::Ed25519 { .. } => "ED25519",
            Data::Ed25519Sk { .. } => "ED25519_SK",
            Data::Ecdsa { .. } => "ECDSA",
            Data::EcdsaSk { .. } => "ECDSA_SK",
        };

        let comment = self
            .comment
            .clone()
            .unwrap_or_else(|| "no comment".to_string());
        format!(
            "{} SHA256:{} {} ({})",
            self.size(),
            self.fingerprint(),
            comment,
            keytype
        )
    }

    /// fingerprint_m5 returns a string representing the fingerprint of the ssh key
    /// the format of the fingerprint is MD5, and the output looks like,
    /// `fb:a0:5b:a0:21:01:47:33:3b:8d:9e:14:1a:4c:db:6d` .
    pub fn fingerprint_md5(&self) -> String {
        let mut sh = Md5::default();
        sh.update(self.data());

        let md5: Vec<String> = sh.finalize().iter().map(|n| format!("{:02x}", n)).collect();
        md5.join(":")
    }

    /// to_fingerprint_m5_string prints out the fingerprint in the in hex format used
    /// by `ssh-keygen -l -E md5 -f key`, and the output looks like,
    /// `2048 MD5:fb:a0:5b:a0:21:01:47:33:3b:8d:9e:14:1a:4c:db:6d demos@anduin (RSA)` .
    pub fn to_fingerprint_md5_string(&self) -> String {
        let keytype = match self.data {
            Data::Rsa { .. } => "RSA",
            Data::Dsa { .. } => "DSA",
            Data::Ed25519 { .. } => "ED25519",
            Data::Ed25519Sk { .. } => "ED25519_SK",
            Data::Ecdsa { .. } => "ECDSA",
            Data::EcdsaSk { .. } => "ECDSA_SK",
        };

        let comment = self
            .comment
            .clone()
            .unwrap_or_else(|| "no comment".to_string());
        format!(
            "{} MD5:{} {} ({})",
            self.size(),
            self.fingerprint_md5(),
            comment,
            keytype
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RSA_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCYH3vPUJThzriVlVKmKOg71EOVYm274oRa5KLWEoK0HmjMc9ru0j4ofouoeW/AVmRVujxfaIGR/8en/lUPkiv5DSeM6aXnDz5cExNptrAy/sMPLQhVALRrqQ+dkS9Ct/YA+A1Le5LPh4MJu79hCDLTwqSdKqDuUcYQzR0M7APslaDCR96zY+VUL4lKObUUd4wsP3opdTQ6G20qXEer14EPGr9N53S/u+JJGLoPlb1uPIH96oKY4t/SeLIRQsocdViRaiF/Aq7kPzWd/yCLVdXJSRt3CftboV4kLBHGteTS551J32MJoqjEi4Q/DucWYrQfx5H3qXVB+/G2HurKPIHL demos@siril";
    const TEST_RSA_COMMENT_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCYH3vPUJThzriVlVKmKOg71EOVYm274oRa5KLWEoK0HmjMc9ru0j4ofouoeW/AVmRVujxfaIGR/8en/lUPkiv5DSeM6aXnDz5cExNptrAy/sMPLQhVALRrqQ+dkS9Ct/YA+A1Le5LPh4MJu79hCDLTwqSdKqDuUcYQzR0M7APslaDCR96zY+VUL4lKObUUd4wsP3opdTQ6G20qXEer14EPGr9N53S/u+JJGLoPlb1uPIH96oKY4t/SeLIRQsocdViRaiF/Aq7kPzWd/yCLVdXJSRt3CftboV4kLBHGteTS551J32MJoqjEi4Q/DucWYrQfx5H3qXVB+/G2HurKPIHL test";
    const TEST_DSA_KEY: &str = "ssh-dss AAAAB3NzaC1kc3MAAACBAIkd9CkqldM2St8f53rfJT7kPgiA8leZaN7hdZd48hYJyKzVLoPdBMaGFuOwGjv0Im3JWqWAewANe0xeLceQL0rSFbM/mZV+1gc1nm1WmtVw4KJIlLXl3gS7NYfQ9Ith4wFnZd/xhRz9Q+MBsA1DgXew1zz4dLYI46KmFivJ7XDzAAAAFQC8z4VIhI4HlHTvB7FdwAfqWsvcOwAAAIBEqPIkW3HHDTSEhUhhV2AlIPNwI/bqaCXy2zYQ6iTT3oUh+N4xlRaBSvW+h2NC97U8cxd7Y0dXIbQKPzwNzRX1KA1F9WAuNzrx9KkpCg2TpqXShhp+Sseb+l6uJjthIYM6/0dvr9cBDMeExabPPgBo3Eii2NLbFSqIe86qav8hZAAAAIBk5AetZrG8varnzv1khkKh6Xq/nX9r1UgIOCQos2XOi2ErjlB9swYCzReo1RT7dalITVi7K9BtvJxbutQEOvN7JjJnPJs+M3OqRMMF+anXPdCWUIBxZUwctbkAD5joEjGDrNXHQEw9XixZ9p3wudbISnPFgZhS1sbS9Rlw5QogKg== demos@siril";
    const TEST_ED25519_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril";
    const TEST_ED25519_SK_KEY: &str = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEX/dQ0v4127bEo8eeG1EV0ApO2lWbSnN6RWusn/NjqIAAAABHNzaDo= demos@siril";
    const TEST_ECDSA256_KEY: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIhfLQrww4DlhYzbSWXoX3ctOQ0jVosvfHfW+QWVotksbPzM2YgkIikTpoHUfZrYpJKWx7WYs5aqeLkdCDdk+jk= demos@siril";
    const TEST_ECDSA_SK_KEY: &str = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBDZ+f5tSRhlB7EN39f93SscTN5PUvbD3UQsNrlE1ZdbwPMMRul2zlPiUvwAvnJitW0jlD/vwZOW2YN+q+iZ5c0MAAAAEc3NoOg== demos@siril";

    #[test]
    fn rsa_parse_to_string() {
        let key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        let out = key.to_string();
        assert_eq!(TEST_RSA_KEY, out);
    }

    #[test]
    fn rsa_size() {
        let key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        assert_eq!(2048, key.size());
    }

    #[test]
    fn rsa_keytype() {
        let key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        assert_eq!("ssh-rsa", key.keytype());
    }

    #[test]
    fn rsa_fingerprint() {
        let key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        assert_eq!(
            "YTw/JyJmeAAle1/7zuZkPP0C73BQ+6XrFEt2/Wy++2o",
            key.fingerprint()
        );
    }

    #[test]
    fn rsa_fingerprint_string() {
        let key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        assert_eq!(
            "2048 SHA256:YTw/JyJmeAAle1/7zuZkPP0C73BQ+6XrFEt2/Wy++2o demos@siril (RSA)",
            key.to_fingerprint_string()
        );
    }

    #[test]
    fn rsa_fingerprint_md5() {
        let key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        assert_eq!(
            "e9:a1:5b:cd:a3:69:d2:d9:17:cb:09:3e:78:e1:0d:dd",
            key.fingerprint_md5()
        );
    }

    #[test]
    fn rsa_fingerprint_md5_string() {
        let key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        assert_eq!(
            "2048 MD5:e9:a1:5b:cd:a3:69:d2:d9:17:cb:09:3e:78:e1:0d:dd demos@siril (RSA)",
            key.to_fingerprint_md5_string()
        );
    }

    #[test]
    fn rsa_set_comment() {
        let mut key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        key.set_comment("test");
        let out = key.to_string();
        assert_eq!(TEST_RSA_COMMENT_KEY, out);
    }

    #[test]
    fn dsa_parse_to_string() {
        let key = PublicKey::parse(TEST_DSA_KEY).unwrap();
        let out = key.to_string();
        assert_eq!(TEST_DSA_KEY, out);
    }

    #[test]
    fn dsa_size() {
        let key = PublicKey::parse(TEST_DSA_KEY).unwrap();
        assert_eq!(1024, key.size());
    }

    #[test]
    fn dsa_keytype() {
        let key = PublicKey::parse(TEST_DSA_KEY).unwrap();
        assert_eq!("ssh-dss", key.keytype());
    }

    #[test]
    fn dsa_fingerprint() {
        let key = PublicKey::parse(TEST_DSA_KEY).unwrap();
        assert_eq!(
            "/Pyxrjot1Hs5PN2Dpg/4pK2wxxtP9Igc3sDTAWIEXT4",
            key.fingerprint()
        );
    }

    #[test]
    fn dsa_fingerprint_string() {
        let key = PublicKey::parse(TEST_DSA_KEY).unwrap();
        assert_eq!(
            "1024 SHA256:/Pyxrjot1Hs5PN2Dpg/4pK2wxxtP9Igc3sDTAWIEXT4 demos@siril (DSA)",
            key.to_fingerprint_string()
        );
    }

    #[test]
    fn ed25519_parse_to_string() {
        let key = PublicKey::parse(TEST_ED25519_KEY).unwrap();
        let out = key.to_string();
        assert_eq!(TEST_ED25519_KEY, out);
    }

    #[test]
    fn ed25519_size() {
        let key = PublicKey::parse(TEST_ED25519_KEY).unwrap();
        assert_eq!(256, key.size());
    }

    #[test]
    fn ed25519_keytype() {
        let key = PublicKey::parse(TEST_ED25519_KEY).unwrap();
        assert_eq!("ssh-ed25519", key.keytype());
    }

    #[test]
    fn ed25519_fingerprint() {
        let key = PublicKey::parse(TEST_ED25519_KEY).unwrap();
        assert_eq!(
            "A/lHzXxsgbp11dcKKfSDyNQIdep7EQgZEoRYVDBfNdI",
            key.fingerprint()
        );
    }

    #[test]
    fn ed25519_fingerprint_string() {
        let key = PublicKey::parse(TEST_ED25519_KEY).unwrap();
        assert_eq!(
            "256 SHA256:A/lHzXxsgbp11dcKKfSDyNQIdep7EQgZEoRYVDBfNdI demos@siril (ED25519)",
            key.to_fingerprint_string()
        );
    }

    #[test]
    fn ed25519_sk_parse_to_string() {
        let key = PublicKey::parse(TEST_ED25519_SK_KEY).unwrap();
        let out = key.to_string();
        assert_eq!(TEST_ED25519_SK_KEY, out);
    }

    #[test]
    fn ed25519_sk_size() {
        let key = PublicKey::parse(TEST_ED25519_SK_KEY).unwrap();
        assert_eq!(256, key.size());
    }

    #[test]
    fn ed25519_sk_keytype() {
        let key = PublicKey::parse(TEST_ED25519_SK_KEY).unwrap();
        assert_eq!("sk-ssh-ed25519@openssh.com", key.keytype());
    }

    #[test]
    fn ed25519_sk_fingerprint() {
        let key = PublicKey::parse(TEST_ED25519_SK_KEY).unwrap();
        assert_eq!(
            "U8IKRkIHed6vFMTflwweA3HhIf2DWgZ8EFTm9fgwOUk",
            key.fingerprint()
        );
    }

    #[test]
    fn ed25519_sk_fingerprint_string() {
        let key = PublicKey::parse(TEST_ED25519_SK_KEY).unwrap();
        assert_eq!(
            "256 SHA256:U8IKRkIHed6vFMTflwweA3HhIf2DWgZ8EFTm9fgwOUk demos@siril (ED25519_SK)",
            key.to_fingerprint_string()
        );
    }

    #[test]
    fn ecdsa256_parse_to_string() {
        let key = PublicKey::parse(TEST_ECDSA256_KEY).unwrap();
        let out = key.to_string();
        assert_eq!(TEST_ECDSA256_KEY, out);
    }

    #[test]
    fn ecdsa256_size() {
        let key = PublicKey::parse(TEST_ECDSA256_KEY).unwrap();
        assert_eq!(256, key.size());
    }

    #[test]
    fn ecdsa256_keytype() {
        let key = PublicKey::parse(TEST_ECDSA256_KEY).unwrap();
        assert_eq!("ecdsa-sha2-nistp256", key.keytype());
    }

    #[test]
    fn ecdsa256_fingerprint() {
        let key = PublicKey::parse(TEST_ECDSA256_KEY).unwrap();
        assert_eq!(
            "BzS5YXMW/d2vFk8Oqh+nKmvKr8X/FTLBfJgDGLu5GAs",
            key.fingerprint()
        );
    }

    #[test]
    fn ecdsa256_fingerprint_string() {
        let key = PublicKey::parse(TEST_ECDSA256_KEY).unwrap();
        assert_eq!(
            "256 SHA256:BzS5YXMW/d2vFk8Oqh+nKmvKr8X/FTLBfJgDGLu5GAs demos@siril (ECDSA)",
            key.to_fingerprint_string()
        );
    }

    #[test]
    fn ecdsa_sk_parse_to_string() {
        let key = PublicKey::parse(TEST_ECDSA_SK_KEY).unwrap();
        let out = key.to_string();
        assert_eq!(TEST_ECDSA_SK_KEY, out);
    }

    #[test]
    fn ecdsa_sk_size() {
        let key = PublicKey::parse(TEST_ECDSA_SK_KEY).unwrap();
        assert_eq!(256, key.size());
    }

    #[test]
    fn ecdsa_sk_keytype() {
        let key = PublicKey::parse(TEST_ECDSA_SK_KEY).unwrap();
        assert_eq!("sk-ecdsa-sha2-nistp256@openssh.com", key.keytype());
    }

    #[test]
    fn ecdsa_sk_fingerprint() {
        let key = PublicKey::parse(TEST_ECDSA_SK_KEY).unwrap();
        assert_eq!(
            "N0sNKBgWKK8usPuPegtgzHQQA9vQ/dRhAEhwFDAnLA4",
            key.fingerprint()
        );
    }

    #[test]
    fn ecdsa_sk_fingerprint_string() {
        let key = PublicKey::parse(TEST_ECDSA_SK_KEY).unwrap();
        assert_eq!(
            "256 SHA256:N0sNKBgWKK8usPuPegtgzHQQA9vQ/dRhAEhwFDAnLA4 demos@siril (ECDSA_SK)",
            key.to_fingerprint_string()
        );
    }

    #[test]
    fn option_parse() {
        let key = PublicKey::parse("agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril").unwrap();
        assert_eq!(Some("agent-forwarding".into()), key.options);
        assert_eq!("agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril", key.to_string());
        let key = PublicKey::parse("from=\"*.sales.example.net,!pc.sales.example.net\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril").unwrap();
        assert_eq!(
            Some("from=\"*.sales.example.net,!pc.sales.example.net\"".into()),
            key.options
        );
        assert_eq!("from=\"*.sales.example.net,!pc.sales.example.net\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril", key.to_string());
        let key = PublicKey::parse("permitopen=\"192.0.2.1:80\",permitopen=\"192.0.2.2:25\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril").unwrap();
        assert_eq!(
            Some("permitopen=\"192.0.2.1:80\",permitopen=\"192.0.2.2:25\"".into()),
            key.options
        );
        assert_eq!("permitopen=\"192.0.2.1:80\",permitopen=\"192.0.2.2:25\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril", key.to_string());
        let key = PublicKey::parse("command=\"echo \\\"holy shell escaping batman\\\"\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril").unwrap();
        assert_eq!(
            Some("command=\"echo \\\"holy shell escaping batman\\\"\"".into()),
            key.options
        );
        assert_eq!("command=\"echo \\\"holy shell escaping batman\\\"\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril", key.to_string());
        let key = PublicKey::parse("command=\"dump /home\",no-pty,no-port-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril").unwrap();
        assert_eq!(
            Some("command=\"dump /home\",no-pty,no-port-forwarding".into()),
            key.options
        );
        assert_eq!("command=\"dump /home\",no-pty,no-port-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril", key.to_string());
    }

    #[test]
    fn hostname_parse() {
        let key = PublicKey::parse("ec2-52-53-211-129.us-west-1.compute.amazonaws.com,52.53.211.129 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFHnC16I49ccjBo68lvN1+zpnAuTGbZjHFi2JRgPZK5o02UDCrFYCUhuS3oCh75+6YmVyReLZAyAM7S/5wjMzTY=").unwrap();
        assert_eq!(
            Some("ec2-52-53-211-129.us-west-1.compute.amazonaws.com,52.53.211.129".into()),
            key.options
        );
        assert_eq!("ec2-52-53-211-129.us-west-1.compute.amazonaws.com,52.53.211.129 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFHnC16I49ccjBo68lvN1+zpnAuTGbZjHFi2JRgPZK5o02UDCrFYCUhuS3oCh75+6YmVyReLZAyAM7S/5wjMzTY=", key.to_string().trim());
        let key = PublicKey::parse("[fangorn.csh.rit.edu]:9090,[129.21.50.131]:9090 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAopjUBQqif5ILeoMHjJ9wGlGs2eNHEv3+OAiiEDHCapNm3guNa+T/ZMtedaC/0P8bLBCXMiyNQU04N/IRyN3Mp/SGhtGJl1PDENXzPB9aoxsB2HHc8s8P7mxal1G4BtCT/fJM5XywEHWAcHkzW91iTK+ApAdqt6AHj35ogil9maFlUNKcXz2aW27hdbDtC0fautvWd9RIITHPq00rdvaHjRcc2msv8LddhBkStP8FrB39RPu9M+ikBkTwdQTSGcIBDYJgt3la2KMwmU1F81cq17wb21lPriBwr626lBiir/WdrBsoAsANeZfyzpAm8K4ssI3eu9eklxpEKdAdNRJbpQ==").unwrap();
        assert_eq!(
            Some("[fangorn.csh.rit.edu]:9090,[129.21.50.131]:9090".into()),
            key.options
        );
        assert_eq!("[fangorn.csh.rit.edu]:9090,[129.21.50.131]:9090 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAopjUBQqif5ILeoMHjJ9wGlGs2eNHEv3+OAiiEDHCapNm3guNa+T/ZMtedaC/0P8bLBCXMiyNQU04N/IRyN3Mp/SGhtGJl1PDENXzPB9aoxsB2HHc8s8P7mxal1G4BtCT/fJM5XywEHWAcHkzW91iTK+ApAdqt6AHj35ogil9maFlUNKcXz2aW27hdbDtC0fautvWd9RIITHPq00rdvaHjRcc2msv8LddhBkStP8FrB39RPu9M+ikBkTwdQTSGcIBDYJgt3la2KMwmU1F81cq17wb21lPriBwr626lBiir/WdrBsoAsANeZfyzpAm8K4ssI3eu9eklxpEKdAdNRJbpQ==", key.to_string().trim());
        let key = PublicKey::parse("@revoked [fangorn.csh.rit.edu]:9090,[129.21.50.131]:9090 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAopjUBQqif5ILeoMHjJ9wGlGs2eNHEv3+OAiiEDHCapNm3guNa+T/ZMtedaC/0P8bLBCXMiyNQU04N/IRyN3Mp/SGhtGJl1PDENXzPB9aoxsB2HHc8s8P7mxal1G4BtCT/fJM5XywEHWAcHkzW91iTK+ApAdqt6AHj35ogil9maFlUNKcXz2aW27hdbDtC0fautvWd9RIITHPq00rdvaHjRcc2msv8LddhBkStP8FrB39RPu9M+ikBkTwdQTSGcIBDYJgt3la2KMwmU1F81cq17wb21lPriBwr626lBiir/WdrBsoAsANeZfyzpAm8K4ssI3eu9eklxpEKdAdNRJbpQ==").unwrap();
        assert_eq!(
            Some("@revoked [fangorn.csh.rit.edu]:9090,[129.21.50.131]:9090".into()),
            key.options
        );
        assert_eq!("@revoked [fangorn.csh.rit.edu]:9090,[129.21.50.131]:9090 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAopjUBQqif5ILeoMHjJ9wGlGs2eNHEv3+OAiiEDHCapNm3guNa+T/ZMtedaC/0P8bLBCXMiyNQU04N/IRyN3Mp/SGhtGJl1PDENXzPB9aoxsB2HHc8s8P7mxal1G4BtCT/fJM5XywEHWAcHkzW91iTK+ApAdqt6AHj35ogil9maFlUNKcXz2aW27hdbDtC0fautvWd9RIITHPq00rdvaHjRcc2msv8LddhBkStP8FrB39RPu9M+ikBkTwdQTSGcIBDYJgt3la2KMwmU1F81cq17wb21lPriBwr626lBiir/WdrBsoAsANeZfyzpAm8K4ssI3eu9eklxpEKdAdNRJbpQ==", key.to_string().trim());
        let key = PublicKey::parse("@cert-authority [fangorn.csh.rit.edu]:9090,[129.21.50.131]:9090 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAopjUBQqif5ILeoMHjJ9wGlGs2eNHEv3+OAiiEDHCapNm3guNa+T/ZMtedaC/0P8bLBCXMiyNQU04N/IRyN3Mp/SGhtGJl1PDENXzPB9aoxsB2HHc8s8P7mxal1G4BtCT/fJM5XywEHWAcHkzW91iTK+ApAdqt6AHj35ogil9maFlUNKcXz2aW27hdbDtC0fautvWd9RIITHPq00rdvaHjRcc2msv8LddhBkStP8FrB39RPu9M+ikBkTwdQTSGcIBDYJgt3la2KMwmU1F81cq17wb21lPriBwr626lBiir/WdrBsoAsANeZfyzpAm8K4ssI3eu9eklxpEKdAdNRJbpQ==").unwrap();
        assert_eq!(
            Some("@cert-authority [fangorn.csh.rit.edu]:9090,[129.21.50.131]:9090".into()),
            key.options
        );
        assert_eq!("@cert-authority [fangorn.csh.rit.edu]:9090,[129.21.50.131]:9090 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAopjUBQqif5ILeoMHjJ9wGlGs2eNHEv3+OAiiEDHCapNm3guNa+T/ZMtedaC/0P8bLBCXMiyNQU04N/IRyN3Mp/SGhtGJl1PDENXzPB9aoxsB2HHc8s8P7mxal1G4BtCT/fJM5XywEHWAcHkzW91iTK+ApAdqt6AHj35ogil9maFlUNKcXz2aW27hdbDtC0fautvWd9RIITHPq00rdvaHjRcc2msv8LddhBkStP8FrB39RPu9M+ikBkTwdQTSGcIBDYJgt3la2KMwmU1F81cq17wb21lPriBwr626lBiir/WdrBsoAsANeZfyzpAm8K4ssI3eu9eklxpEKdAdNRJbpQ==", key.to_string().trim());
    }

    #[test]
    fn read_keys() {
        let authorized_keys = "# authorized keys

command=\"echo \\\"holy shell escaping batman\\\"\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril
agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril




ssh-dss AAAAB3NzaC1kc3MAAACBAIkd9CkqldM2St8f53rfJT7kPgiA8leZaN7hdZd48hYJyKzVLoPdBMaGFuOwGjv0Im3JWqWAewANe0xeLceQL0rSFbM/mZV+1gc1nm1WmtVw4KJIlLXl3gS7NYfQ9Ith4wFnZd/xhRz9Q+MBsA1DgXew1zz4dLYI46KmFivJ7XDzAAAAFQC8z4VIhI4HlHTvB7FdwAfqWsvcOwAAAIBEqPIkW3HHDTSEhUhhV2AlIPNwI/bqaCXy2zYQ6iTT3oUh+N4xlRaBSvW+h2NC97U8cxd7Y0dXIbQKPzwNzRX1KA1F9WAuNzrx9KkpCg2TpqXShhp+Sseb+l6uJjthIYM6/0dvr9cBDMeExabPPgBo3Eii2NLbFSqIe86qav8hZAAAAIBk5AetZrG8varnzv1khkKh6Xq/nX9r1UgIOCQos2XOi2ErjlB9swYCzReo1RT7dalITVi7K9BtvJxbutQEOvN7JjJnPJs+M3OqRMMF+anXPdCWUIBxZUwctbkAD5joEjGDrNXHQEw9XixZ9p3wudbISnPFgZhS1sbS9Rlw5QogKg==
";
        let key1 = "command=\"echo \\\"holy shell escaping batman\\\"\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril";
        let key2 = "agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ demos@siril";
        let key3 = "ssh-dss AAAAB3NzaC1kc3MAAACBAIkd9CkqldM2St8f53rfJT7kPgiA8leZaN7hdZd48hYJyKzVLoPdBMaGFuOwGjv0Im3JWqWAewANe0xeLceQL0rSFbM/mZV+1gc1nm1WmtVw4KJIlLXl3gS7NYfQ9Ith4wFnZd/xhRz9Q+MBsA1DgXew1zz4dLYI46KmFivJ7XDzAAAAFQC8z4VIhI4HlHTvB7FdwAfqWsvcOwAAAIBEqPIkW3HHDTSEhUhhV2AlIPNwI/bqaCXy2zYQ6iTT3oUh+N4xlRaBSvW+h2NC97U8cxd7Y0dXIbQKPzwNzRX1KA1F9WAuNzrx9KkpCg2TpqXShhp+Sseb+l6uJjthIYM6/0dvr9cBDMeExabPPgBo3Eii2NLbFSqIe86qav8hZAAAAIBk5AetZrG8varnzv1khkKh6Xq/nX9r1UgIOCQos2XOi2ErjlB9swYCzReo1RT7dalITVi7K9BtvJxbutQEOvN7JjJnPJs+M3OqRMMF+anXPdCWUIBxZUwctbkAD5joEjGDrNXHQEw9XixZ9p3wudbISnPFgZhS1sbS9Rlw5QogKg== ";
        let keys = PublicKey::read_keys(authorized_keys.as_bytes()).unwrap();
        assert_eq!(key1, keys[0].to_string());
        assert_eq!(key2, keys[1].to_string());
        assert_eq!(key3, keys[2].to_string());
    }

    #[test]
    fn comment_should_be_none_when_absent() {
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/";
        let key = PublicKey::parse(key).unwrap();
        assert!(key.comment.is_none());
    }

    #[test]
    fn comment_should_be_none_when_empty_string() {
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/    ";
        let key = PublicKey::parse(key).unwrap();
        assert!(key.comment.is_none());
    }

    #[test]
    fn comment_should_preserve_special_characters() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ !@#$%^&*()_+-={}|[]\\:\";'<>?,./";
        let key = PublicKey::parse(key).unwrap();
        assert_eq!(key.comment.unwrap(), "!@#$%^&*()_+-={}|[]\\:\";'<>?,./");
    }

    #[test]
    fn comment_should_preserve_multiple_spaces() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ comment with multiple   spaces";
        let key = PublicKey::parse(key).unwrap();
        assert_eq!(key.comment.unwrap(), "comment with multiple   spaces");
    }

    #[test]
    fn comment_should_remove_leading_and_trailing_spaces_while_keeping_body_intact() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/   leading and trailing   spaces are trimmed   ";
        let key = PublicKey::parse(key).unwrap();
        assert_eq!(
            key.comment.unwrap(),
            "leading and trailing   spaces are trimmed"
        );
    }

    #[test]
    fn comment_should_not_preserve_newlines() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ comment with\nnewlines";
        let key = PublicKey::parse(key);
        assert!(key.is_err());
    }

    #[test]
    fn comment_should_preserve_mixed_whitespace() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ mixed white\t space";
        let key = PublicKey::parse(key).unwrap();
        assert_eq!(key.comment.unwrap(), "mixed white\t space");
    }

    #[test]
    fn comment_should_preserve_unicode_characters() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhBr6++FQXB8kkgOMbdxBuyrHzuX5HkElswrN6DQoN/ comment with unicode: 中文, русский, عربى";
        let key = PublicKey::parse(key).unwrap();
        assert_eq!(
            key.comment.unwrap(),
            "comment with unicode: 中文, русский, عربى"
        );
    }
}
