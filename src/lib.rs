//! ssh-keys
//!
//! this library provides pure-rust parsing, manipulation, and validation of
//! ssh keys. it provides a struct for encapsulation of ssh keys in projects.
#![allow(unused_doc_comment)]

extern crate base64;
extern crate byteorder;
extern crate crypto;
#[macro_use]
extern crate error_chain;

mod reader;
mod writer;

mod errors {
    error_chain! {
        foreign_links {
            Utf8(::std::str::Utf8Error);
        }
        errors {
            InvalidFormat {
                description("invalid key format")
                    display("invalid key format")
            }
            UnsupportedKeytype(t: String) {
                description("unsupported keytype")
                    display("unsupported keytype: {}", t)
            }
        }
    }
}

use errors::*;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use reader::Reader;
use writer::Writer;

/// PublicKey is the enum representation of a public key
/// currently it only supports holding RSA public keys
#[derive(Clone, Debug)]
pub enum PublicKey {
    Rsa {
        exponent: Vec<u8>,
        modulus: Vec<u8>,
    },
}

impl PublicKey {
    /// parse takes a string and reads from it an ssh public key
    /// it uses the first part of the key to determine the keytype
    /// the format it expects is described here https://tools.ietf.org/html/rfc4253#section-6.6
    pub fn parse(key: &str) -> Result<Self> {
        let mut parts = key.split_whitespace();
        let keytype = parts.next().ok_or(ErrorKind::InvalidFormat)?;
        let data = parts.next().ok_or(ErrorKind::InvalidFormat)?;

        let buf = base64::decode(data)
            .chain_err(|| ErrorKind::InvalidFormat)?;
        let mut reader = Reader::new(&buf);
        let data_keytype = reader.read_string()?;
        if keytype != data_keytype {
            return Err(ErrorKind::InvalidFormat.into());
        }

        match keytype {
            "ssh-rsa" => {
                // the data for an rsa key consists of three pieces:
                //    ssh-rsa public-exponent modulus
                // see ssh-rsa format in https://tools.ietf.org/html/rfc4253#section-6.6
                let e = reader.read_mpint()?;
                let n = reader.read_mpint()?;
                Ok(PublicKey::Rsa {
                    exponent: e.into(),
                    modulus: n.into(),
                })
            },
            _ => Err(ErrorKind::UnsupportedKeytype(keytype.into()).into()),
        }
    }

    /// get an ssh public key from rsa components
    pub fn from_rsa(e: Vec<u8>, n: Vec<u8>) -> Self {
        PublicKey::Rsa {
            exponent: e,
            modulus: n,
        }
    }

    /// keytype returns the type of key in the format described by rfc4253
    pub fn keytype(&self) -> &'static str {
        match *self {
            PublicKey::Rsa{..} => "ssh-rsa",
        }
    }

    /// data returns the data section of the key in the format described by rfc4253
    pub fn data(&self) -> Vec<u8> {
        match *self {
            PublicKey::Rsa{ref exponent, ref modulus} => {
                // the data for an rsa key consists of three pieces:
                //    ssh-rsa public-exponent modulus
                // see ssh-rsa format in https://tools.ietf.org/html/rfc4253#section-6.6
                let mut writer = Writer::new();
                writer.write_string(self.keytype());
                writer.write_mpint(exponent.clone());
                writer.write_mpint(modulus.clone());
                writer.to_vec()
            }
        }
    }

    /// to_string returns a string representation of the ssh key
    /// this string output is appropriate to use as a public key file
    /// it adheres to the format described in https://tools.ietf.org/html/rfc4253#section-6.6
    /// an ssh key consists of three pieces:
    ///    ssh-keytype data comment
    /// each of those is encoded as big-endian bytes preceeded by four bytes
    /// representing their length.
    pub fn to_string(self, comment: &str) -> String {
        format!("{} {} {}", self.keytype(), base64::encode(&self.data()), comment)
    }

    /// size returns the size of the stored ssh key
    /// for rsa keys this is determined by the number of bits in the modulus
    pub fn size(&self) -> usize {
        match *self {
            PublicKey::Rsa{ref modulus,..} => modulus.len()*8,
        }
    }

    /// fingerprint returns a string representing the fingerprint of the ssh key
    /// the format of the fingerprint is described tersely in
    /// https://tools.ietf.org/html/rfc4716#page-6, but in particular, this
    /// implementation tends towards the concrete behavior used by the openssh
    /// implementation itself https://github.com/openssh/openssh-portable/blob/master/ssh-keygen.c#L842
    /// right now it just sticks with the defaults of a base64 encoded SHA256 hash
    pub fn fingerprint(&self) -> String {
        let data = self.data();
        let mut hasher = Sha256::new();
        hasher.input(&data);
        let mut hashed: [u8; 32] = [0; 32];
        hasher.result(&mut hashed);
        let mut fingerprint = base64::encode(&hashed);
        // trim padding characters off the end
        // not clear on exactly what this is doing but they do it here
        // https://github.com/openssh/openssh-portable/blob/643c2ad82910691b2240551ea8b14472f60b5078/sshkey.c#L918
        match fingerprint.find('=') {
            Some(l) => { fingerprint.split_off(l); },
            None => {},
        }
        format!("SHA256:{}", fingerprint)
    }

    pub fn to_fingerprint_string(&self) -> String {
        let keytype = match *self {
            PublicKey::Rsa{..} => "RSA",
        };

        format!("{} {} {} ({})", self.size(), self.fingerprint(), "no comment", keytype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RSA_KEY: &'static str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcMCOEryBa8IkxXacjIawaQPp08hR5h7+4vZePZ7DByTG3tqKgZYRJ86BaR+4fmdikFoQjvLJVUmwniq3wixhkP7VLCbqip3YHzxXrzxkbPC3w3O1Bdmifwn9cb8RcZXfXncCsSu+h5XCtQ5BOi41Iit3d13gIe/rfXVDURmRanV6R7Voljxdjmp/zyReuzc2/w5SI6Boi4tmcUlxAI7sFuP1kA3pABDhPtc3TDgAcPUIBoDCoY8q2egI197UuvbgsW2qraUcuQxbMvJOMSFg2FQrE2bpEqC4CtBn7+HiJrkVOHjV7bvSv7jd1SuX5XqkwMCRtdMuRpJr7CyZoFL5n demos@anduin";

    #[test]
    fn rsa_parse_to_string() {
        let key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        let out = key.to_string("demos@anduin");
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
        assert_eq!("SHA256:96eJ3PXgBcuIcwLllSxpHcv8Ewie6oev60Pkmu3pDE8", key.fingerprint());
    }

    #[test]
    fn rsa_fingerprint_string() {
        let key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        assert_eq!("2048 SHA256:96eJ3PXgBcuIcwLllSxpHcv8Ewie6oev60Pkmu3pDE8 no comment (RSA)", key.to_fingerprint_string());
    }
}
