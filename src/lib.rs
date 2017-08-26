//! ssh-keys
//!
//! this library provides pure-rust parsing, manipulation, and validation of
//! ssh keys. it provides a struct for encapsulation of ssh keys in projects.
#![allow(unused_doc_comment)]

extern crate base64;
extern crate byteorder;
#[macro_use]
extern crate error_chain;
extern crate openssl;

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

use byteorder::{WriteBytesExt, BigEndian, ByteOrder};

use openssl::rsa::Rsa;

#[derive(Clone, Debug)]
pub enum PublicKey {
    Rsa {
        exponent: Vec<u8>,
        modulus: Vec<u8>,
    },
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

struct Writer {
    data: Vec<u8>,
}

impl PublicKey {
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
                let e = reader.read_bytes()?;
                let n = reader.read_bytes()?;
                Ok(PublicKey::Rsa {
                    exponent: e.into(),
                    modulus: n.into(),
                })
            },
            _ => Err(ErrorKind::UnsupportedKeytype(keytype.into()).into()),
        }
    }

    /// get an ssh public key from an openssl Rsa key
    /// panics if for some reason the Rsa key doesn't have an e or n component
    pub fn from_rsa(rsa: &Rsa) -> Self {
        PublicKey::Rsa {
            exponent: rsa.e().unwrap().to_vec(),
            modulus: rsa.n().unwrap().to_vec(),
        }
    }

    // an ssh key consists of three pieces:
    //    ssh-keytype data comment
    // each of those is encoded as big-endian bytes preceeded by four bytes
    // representing their length.
    pub fn to_string(self, comment: &str) -> String {
        // get the keytype for this key
        let keytype = match self {
            PublicKey::Rsa{..} => "ssh-rsa",
        };

        let data = match self {
            PublicKey::Rsa{exponent, modulus} => {
                // the data for an rsa key consists of three pieces:
                //    ssh-rsa public-exponent modulus
                // see ssh-rsa format in https://tools.ietf.org/html/rfc4253#section-6.6
                let mut writer = Writer::new();
                writer.write_string(keytype);
                writer.write_mpint(exponent);
                writer.write_mpint(modulus);
                writer.to_vec()
            }
        };

        // the data section is base64 encoded
        let data = base64::encode(&data);

        format!("{} {} {}", keytype, data, comment)
    }
}

impl Writer {
    pub fn new() -> Writer {
        Writer {data: vec![]}
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.data
    }

    pub fn write_int(&mut self, val: u32) {
        match self.data.write_u32::<BigEndian>(val) {
            Err(..) => unreachable!(),
            _ => {},
        }
    }

    pub fn write_bytes(&mut self, mut buf: Vec<u8>) {
        // The first four bytes represent the length of the encoded data.
        self.write_int(buf.len() as u32);
        // the rest of the bytes are the data itself
        self.data.append(&mut buf);
    }

    // according to RFC 4251, the mpint datatype representation is a big-endian
    // arbitrary-precision integer stored in two's compliment and stored as a
    // string with the minimum possible number of characters.
    // see mpint definition in https://tools.ietf.org/html/rfc4251#section-5
    fn write_mpint(&mut self, mut num: Vec<u8>) {
        // If the number is positive then we are required to guarentee that the
        // most significant bit is set to zero if the first bit in the first
        // byte is going to be one.
        if num.get(0).unwrap() & 0x80 != 0 {
            num.insert(0, 0);
        }
        // other than that it's just normal ssh encoding
        self.write_bytes(num)
    }

    fn write_string(&mut self, val: &str) {
        self.write_bytes(val.as_bytes().to_vec())
    }
}

impl<'a> Reader<'a> {
    pub fn new(data: &[u8]) -> Reader {
        Reader {
            data: data,
            offset: 0,
        }
    }

    pub fn peek_int(&mut self) -> Result<u32> {
        let cur = &self.data[self.offset..];
        if cur.len() < 4 {
            return Err(ErrorKind::InvalidFormat.into());
        }
        Ok(BigEndian::read_u32(&cur[..4]))
    }

    pub fn read_int(&mut self) -> Result<u32> {
        let val = self.peek_int()?;
        self.offset += 4;
        Ok(val)
    }

    pub fn read_string(&mut self) -> Result<&'a str> {
        std::str::from_utf8(self.read_bytes()?)
            .chain_err(|| ErrorKind::InvalidFormat)
    }

    pub fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let cur = &self.data[self.offset..];
        let len = self.peek_int()? as usize;
        if cur.len() < len + 4 {
            return Err(ErrorKind::InvalidFormat.into());
        }
        self.offset += len + 4;
        Ok(&cur[4..len+4])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RSA_KEY: &'static str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcMCOEryBa8IkxXacjIawaQPp08hR5h7+4vZePZ7DByTG3tqKgZYRJ86BaR+4fmdikFoQjvLJVUmwniq3wixhkP7VLCbqip3YHzxXrzxkbPC3w3O1Bdmifwn9cb8RcZXfXncCsSu+h5XCtQ5BOi41Iit3d13gIe/rfXVDURmRanV6R7Voljxdjmp/zyReuzc2/w5SI6Boi4tmcUlxAI7sFuP1kA3pABDhPtc3TDgAcPUIBoDCoY8q2egI197UuvbgsW2qraUcuQxbMvJOMSFg2FQrE2bpEqC4CtBn7+HiJrkVOHjV7bvSv7jd1SuX5XqkwMCRtdMuRpJr7CyZoFL5n demos@anduin";

    #[test]
    fn parse_to_string() {
        let key = PublicKey::parse(TEST_RSA_KEY).unwrap();
        let out = key.to_string("demos@anduin");
        assert_eq!(TEST_RSA_KEY, out);
    }
}
