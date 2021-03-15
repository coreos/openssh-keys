//! This module provides a struct for reading bytes in the OpenSSH public key format.

use crate::errors::*;

use byteorder::{BigEndian, ByteOrder};

pub struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &[u8]) -> Reader {
        Reader { data, offset: 0 }
    }

    pub fn peek_int(&mut self) -> Result<u32> {
        let cur = &self.data[self.offset..];
        if cur.len() < 4 {
            return Err(OpenSSHKeyError::InvalidFormat);
        }
        Ok(BigEndian::read_u32(&cur[..4]))
    }

    pub fn read_string(&mut self) -> Result<&'a str> {
        Ok(std::str::from_utf8(self.read_bytes()?)?)
    }

    pub fn read_mpint(&mut self) -> Result<&'a [u8]> {
        // mpints might have an extra byte of zeros at the start.
        // if there is, we can just ignore it, since the number is big-endian
        let bytes = self.read_bytes()?;
        if bytes.get(0) == Some(&0) {
            Ok(&bytes[1..])
        } else {
            Ok(bytes)
        }
    }

    pub fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let cur = &self.data[self.offset..];
        let len = self.peek_int()? as usize;
        if cur.len() < len + 4 {
            return Err(OpenSSHKeyError::InvalidFormat);
        }
        self.offset += len + 4;
        Ok(&cur[4..len + 4])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_empty() {
        let data = vec![];
        let mut rd = Reader::new(data.as_ref());
        assert!(rd.peek_int().is_err());
        assert!(rd.read_bytes().is_err());
        assert!(rd.read_mpint().is_err());
        assert!(rd.read_string().is_err());
    }
}
