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

use std::fmt;

const SSH_RSA: &'static str = "ssh-rsa";

/// PublicKey is the enum representation of a public key
/// currently it only supports holding RSA public keys
#[derive(Clone, Debug)]
pub enum Data {
    Rsa {
        exponent: Vec<u8>,
        modulus: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    keytype: &'static str,
    data: Data,
    comment: Option<String>,
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_key_file())
    }
}

impl PublicKey {
    /// parse takes a string and reads from it an ssh public key
    /// it uses the first part of the key to determine the keytype
    /// the format it expects is described here https://tools.ietf.org/html/rfc4253#section-6.6
    ///
    /// You can parse and output ssh keys like this
    /// ```
    /// let rsa_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcMCOEryBa8IkxXacjIawaQPp08hR5h7+4vZePZ7DByTG3tqKgZYRJ86BaR+4fmdikFoQjvLJVUmwniq3wixhkP7VLCbqip3YHzxXrzxkbPC3w3O1Bdmifwn9cb8RcZXfXncCsSu+h5XCtQ5BOi41Iit3d13gIe/rfXVDURmRanV6R7Voljxdjmp/zyReuzc2/w5SI6Boi4tmcUlxAI7sFuP1kA3pABDhPtc3TDgAcPUIBoDCoY8q2egI197UuvbgsW2qraUcuQxbMvJOMSFg2FQrE2bpEqC4CtBn7+HiJrkVOHjV7bvSv7jd1SuX5XqkwMCRtdMuRpJr7CyZoFL5n demos@anduin";
    /// let key = PublicKey::parse(rsa_key).unwrap();
    /// let out = key.to_string();
    /// assert_eq!(rsa_key, out);
    /// ```
    ///
    /// parse somewhat attempts to keep track of comments, but it doesn't fully
    /// comply with the rfc in that regard.
    pub fn parse(key: &str) -> Result<Self> {
        let mut parts = key.split_whitespace();
        let in_keytype = parts.next().ok_or(ErrorKind::InvalidFormat)?;
        let data = parts.next().ok_or(ErrorKind::InvalidFormat)?;
        // comment is not required. if we get an empty comment (because of a
        // trailing space) throw it out.
        let comment = parts.next().and_then(|c| if c.is_empty() { None } else { Some(c.to_string()) });

        let buf = base64::decode(data)
            .chain_err(|| ErrorKind::InvalidFormat)?;
        let mut reader = Reader::new(&buf);
        let data_keytype = reader.read_string()?;
        if in_keytype != data_keytype {
            return Err(ErrorKind::InvalidFormat.into());
        }

        let keytype: &'static str;

        let data = match in_keytype {
            SSH_RSA => {
                // the data for an rsa key consists of three pieces:
                //    ssh-rsa public-exponent modulus
                // see ssh-rsa format in https://tools.ietf.org/html/rfc4253#section-6.6
                keytype = SSH_RSA;
                let e = reader.read_mpint()?;
                let n = reader.read_mpint()?;
                Data::Rsa {
                    exponent: e.into(),
                    modulus: n.into(),
                }
            },
            _ => return Err(ErrorKind::UnsupportedKeytype(in_keytype.into()).into()),
        };

        Ok(PublicKey {
            keytype: keytype,
            data: data,
            comment: comment,
        })
    }

    /// get an ssh public key from rsa components
    pub fn from_rsa(e: Vec<u8>, n: Vec<u8>) -> Self {
        PublicKey {
            keytype: SSH_RSA,
            data: Data::Rsa {
                exponent: e,
                modulus: n,
            },
            comment: None,
        }
    }

    /// keytype returns the type of key in the format described by rfc4253
    /// The output will be ssh-{type} where type is [rsa,ed25519,ecdsa,dsa]
    pub fn keytype(&self) -> &'static str {
        self.keytype
    }

    /// data returns the data section of the key in the format described by rfc4253
    /// the contents of the data section depend on the keytype. For RSA keys it
    /// contains the keytype, exponent, and modulus in that order. Other types
    /// have other data sections. This function doesn't base64 encode the data,
    /// that task is left to the consumer of the output.
    pub fn data(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_string(self.keytype);
        match self.data {
            Data::Rsa{ref exponent, ref modulus} => {
                // the data for an rsa key consists of three pieces:
                //    ssh-rsa public-exponent modulus
                // see ssh-rsa format in https://tools.ietf.org/html/rfc4253#section-6.6
                writer.write_mpint(exponent.clone());
                writer.write_mpint(modulus.clone());
            }
        }
        writer.to_vec()
    }

    pub fn set_comment(&mut self, comment: &str) {
        self.comment = Some(comment.to_string());
    }

    /// to_string returns a string representation of the ssh key
    /// this string output is appropriate to use as a public key file
    /// it adheres to the format described in https://tools.ietf.org/html/rfc4253#section-6.6
    /// an ssh key consists of three pieces:
    ///    ssh-keytype data comment
    /// each of those is encoded as big-endian bytes preceeded by four bytes
    /// representing their length.
    pub fn to_key_file(&self) -> String {
        format!("{} {} {}", self.keytype, base64::encode(&self.data()), self.comment.clone().unwrap_or_default())
    }

    /// size returns the size of the stored ssh key
    /// for rsa keys this is determined by the number of bits in the modulus
    pub fn size(&self) -> usize {
        match self.data {
            Data::Rsa{ref modulus,..} => modulus.len()*8,
        }
    }

    /// fingerprint returns a string representing the fingerprint of the ssh key
    /// the format of the fingerprint is described tersely in
    /// https://tools.ietf.org/html/rfc4716#page-6. This uses the ssh-keygen
    /// defaults of a base64 encoded SHA256 hash.
    pub fn fingerprint(&self) -> String {
        let data = self.data();
        let mut hasher = Sha256::new();
        hasher.input(&data);
        let mut hashed: [u8; 32] = [0; 32];
        hasher.result(&mut hashed);
        let mut fingerprint = base64::encode(&hashed);
        // trim padding characters off the end. I'm not clear on exactly what
        // this is doing but they do it here and the test fails without it
        // https://github.com/openssh/openssh-portable/blob/643c2ad82910691b2240551ea8b14472f60b5078/sshkey.c#L918
        match fingerprint.find('=') {
            Some(l) => { fingerprint.split_off(l); },
            None => {},
        }
        format!("SHA256:{}", fingerprint)
    }

    /// to_fingerprint_string prints out the fingerprint in the same format used
    /// by `ssh-keygen -l -f key`, specifically the implementation here -
    /// https://github.com/openssh/openssh-portable/blob/master/ssh-keygen.c#L842
    /// right now it just sticks with the defaults of a base64 encoded SHA256
    /// hash.
    pub fn to_fingerprint_string(&self) -> String {
        let keytype = match self.data {
            Data::Rsa{..} => "RSA",
        };

        format!("{} {} {} ({})", self.size(), self.fingerprint(), self.comment.clone().unwrap_or("no comment".to_string()), keytype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RSA_KEY: &'static str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcMCOEryBa8IkxXacjIawaQPp08hR5h7+4vZePZ7DByTG3tqKgZYRJ86BaR+4fmdikFoQjvLJVUmwniq3wixhkP7VLCbqip3YHzxXrzxkbPC3w3O1Bdmifwn9cb8RcZXfXncCsSu+h5XCtQ5BOi41Iit3d13gIe/rfXVDURmRanV6R7Voljxdjmp/zyReuzc2/w5SI6Boi4tmcUlxAI7sFuP1kA3pABDhPtc3TDgAcPUIBoDCoY8q2egI197UuvbgsW2qraUcuQxbMvJOMSFg2FQrE2bpEqC4CtBn7+HiJrkVOHjV7bvSv7jd1SuX5XqkwMCRtdMuRpJr7CyZoFL5n demos@anduin";
    const TEST_RSA_COMMENT_KEY: &'static str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcMCOEryBa8IkxXacjIawaQPp08hR5h7+4vZePZ7DByTG3tqKgZYRJ86BaR+4fmdikFoQjvLJVUmwniq3wixhkP7VLCbqip3YHzxXrzxkbPC3w3O1Bdmifwn9cb8RcZXfXncCsSu+h5XCtQ5BOi41Iit3d13gIe/rfXVDURmRanV6R7Voljxdjmp/zyReuzc2/w5SI6Boi4tmcUlxAI7sFuP1kA3pABDhPtc3TDgAcPUIBoDCoY8q2egI197UuvbgsW2qraUcuQxbMvJOMSFg2FQrE2bpEqC4CtBn7+HiJrkVOHjV7bvSv7jd1SuX5XqkwMCRtdMuRpJr7CyZoFL5n test";

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
        assert_eq!("SHA256:96eJ3PXgBcuIcwLllSxpHcv8Ewie6oev60Pkmu3pDE8", key.fingerprint());
    }

    #[test]
    fn rsa_fingerprint_string() {
        let key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        assert_eq!("2048 SHA256:96eJ3PXgBcuIcwLllSxpHcv8Ewie6oev60Pkmu3pDE8 demos@anduin (RSA)", key.to_fingerprint_string());
    }

    #[test]
    fn rsa_set_comment() {
        let mut key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        key.set_comment("test");
        let out = key.to_string();
        assert_eq!(TEST_RSA_COMMENT_KEY, out);
    }
}
