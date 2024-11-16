use core::panic;
use std::error::Error;
use std::io::BufReader;
use std::io::Read;

use x509_certificate::certificate::X509Certificate;

const MAGIC: [u8; 4] = [0xFE, 0xED, 0xFE, 0xED];

#[derive(PartialEq)]
pub enum Version {
    Unsupported,
    V2,
}

impl From<[u8; 4]> for Version {
    fn from(value: [u8; 4]) -> Self {
        match u32::from_be_bytes(value) {
            2 => Version::V2,
            _ => Version::Unsupported,
        }
    }
}

#[derive(PartialEq)]
pub enum EntryType {
    KeyPair,
    Certs,
}

impl From<[u8; 4]> for EntryType {
    fn from(value: [u8; 4]) -> Self {
        match u32::from_be_bytes(value) {
            1 => EntryType::KeyPair,
            2 => EntryType::Certs,
            _ => panic!("invalid entry type"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Store {
    pub certs: Option<Vec<Cert>>,
    pub key_pairs: Option<Vec<KeyPair>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Cert {
    pub alias: String,
    pub timestamp: u64,
    pub raw: Vec<u8>,
    pub cert: X509Certificate,
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub alias: String,
    pub timestamp: u64,
    pub encrypted_key: Vec<u8>,
    pub raw_key: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Instance {
    pub alias: String,
    pub timestamp: u64,
    key: Option<Vec<u8>>,
    cert: Vec<u8>,
}

impl Store {
    pub fn parse(data: impl AsRef<[u8]>, _password: String) -> Result<Self, Box<dyn Error>> {
        let mut buffer = BufReader::new(data.as_ref());

        let magic = read_u32(&mut buffer)?;
        if !magic.eq(&MAGIC) {
            return Err(format!(
                "invalid file format, expected header '{:#x?}', but got '{:#x?}'",
                MAGIC, magic
            ))?;
        }
        let version = read_u32(&mut buffer)?;
        if Version::from(version) == Version::Unsupported {
            return Err("unsupported version, supported only version 2".to_owned())?;
        }
        let mut keypairs: Vec<KeyPair> = vec![];
        let mut certs: Vec<Cert> = vec![];

        let entries = u32::from_be_bytes(read_u32(&mut buffer)?);
        for _ in 0..entries {
            let entry_type = EntryType::from(read_u32(&mut buffer)?);
            match entry_type {
                EntryType::KeyPair => unimplemented!("key pairs"),
                EntryType::Certs => {
                    let cert = process_cert(&mut buffer)?;
                    certs.push(cert);
                }
            }
        }
        Ok(Store {
            certs: Some(certs),
            key_pairs: Some(keypairs),
        })
    }
}

fn process_cert<T>(data: &mut BufReader<T>) -> Result<Cert, Box<dyn Error>>
where
    T: Read,
{
    let alias = read_str(data)?;
    let timestamp = read_timestamp(data)?;
    let cert_type = read_str(data)?;
    if !cert_type.eq("X.509") {
        return Err(format!("not supported certificate type: {}", cert_type))?;
    }
    let cert_length = read_u32(data)?;
    let cert_der = read_bytes(data, u32::from_be_bytes(cert_length) as usize)?;
    let parsed_cert = X509Certificate::from_der(cert_der.clone())?;
    Ok(Cert {
        alias,
        timestamp,
        raw: cert_der,
        cert: parsed_cert,
    })
}

fn read_bytes<T>(data: &mut BufReader<T>, len: usize) -> Result<Vec<u8>, String>
where
    T: Read,
{
    use std::io::ErrorKind::UnexpectedEof;
    let mut buf: Vec<u8> = vec![0; len];
    match data.read_exact(&mut buf) {
        Ok(_) => Ok(buf),
        Err(e) if e.kind() == UnexpectedEof => Err(format!(
            "buffer is too short, at least {} are required",
            len
        )),
        Err(e) => Err(format!("error reading bytes: {e}")),
    }
}

fn read_u16<T>(data: &mut BufReader<T>) -> Result<[u8; 2], String>
where
    T: Read,
{
    use std::io::ErrorKind::UnexpectedEof;
    let mut buf = [0u8; 2];
    match data.read_exact(&mut buf) {
        Ok(_) => Ok(buf),
        Err(e) if e.kind() == UnexpectedEof => {
            Err("buffer is too short, at least 2 bytes are required".to_owned())
        }
        Err(e) => Err(format!("error reading bytes: {}", e)),
    }
}

fn read_u32<T>(data: &mut BufReader<T>) -> Result<[u8; 4], String>
where
    T: Read,
{
    use std::io::ErrorKind::UnexpectedEof;
    let mut buf = [0u8; 4];
    match data.read_exact(&mut buf) {
        Ok(_) => Ok(buf),
        Err(e) if e.kind() == UnexpectedEof => {
            Err("buffer is too short, at least 4 bytes are required".to_string())
        }
        Err(e) => Err(format!("error reading bytes: {}", e)),
    }
}

fn read_u64<T>(data: &mut BufReader<T>) -> Result<[u8; 8], String>
where
    T: Read,
{
    use std::io::ErrorKind::UnexpectedEof;
    let mut buf = [0u8; 8];
    match data.read_exact(&mut buf) {
        Ok(_) => Ok(buf),
        Err(e) if e.kind() == UnexpectedEof => {
            Err("buffer is too short, at least 8 bytes are required".to_string())
        }
        Err(e) => Err(format!("error reading bytes: {}", e)),
    }
}

fn read_str<T>(data: &mut BufReader<T>) -> Result<String, String>
where
    T: Read,
{
    let length = u16::from_be_bytes(read_u16(data)?);
    let mut buf: Vec<u8> = vec![0; length as usize];
    match data.read_exact(&mut buf) {
        Ok(()) => {}
        Err(e) => return Err(format!("failed to read string: {}", e)),
    }
    match String::from_utf8(buf) {
        Ok(res) => Ok(res),
        Err(e) => Err(format!("{}", e)),
    }
}

fn read_timestamp<T>(data: &mut BufReader<T>) -> Result<u64, String>
where
    T: Read,
{
    let timestamp = read_u64(data)?;
    Ok(u64::from_be_bytes(timestamp))
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn four_bytes_readed() {
        let data = [0xfeu8, 0xed, 0xfe, 0xed, 0x00];
        let cursor = io::Cursor::new(data);
        let mut buf = BufReader::new(cursor);
        let four_bytes = read_u32(&mut buf).unwrap();
        assert_eq!(four_bytes.len(), 4);
        assert_eq!(four_bytes, MAGIC);
        // check buffer contain last 1 bytes
        let mut other = [0u8; 4];
        assert_eq!(buf.read(&mut other).unwrap(), 1);
    }

    #[test]
    fn version() {
        let data = [0x00u8, 0x00, 0x00, 0x02];
        let cursor = io::Cursor::new(data);
        let mut buf = BufReader::new(cursor);
        let four_bytes = read_u32(&mut buf).unwrap();
        let d = u32::from_be_bytes(four_bytes);
        assert_eq!(d, 2);
    }
}
