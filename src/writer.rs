//! writer
//!
//! this crate provides a struct for writing bytes in the OpenSSH public key format.

use byteorder::{WriteBytesExt, BigEndian};

pub struct Writer {
    data: Vec<u8>,
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
    pub fn write_mpint(&mut self, mut num: Vec<u8>) {
        // If the number is positive then we are required to guarentee that the
        // most significant bit is set to zero if the first bit in the first
        // byte is going to be one.
        if num.get(0).unwrap() & 0x80 != 0 {
            num.insert(0, 0);
        }
        // other than that it's just normal ssh encoding
        self.write_bytes(num)
    }

    pub fn write_string(&mut self, val: &str) {
        self.write_bytes(val.as_bytes().to_vec())
    }
}
