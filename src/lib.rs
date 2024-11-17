pub mod read;

use core::panic;
use std::collections::HashMap;
use std::error::Error;
use std::io::{BufReader, Read};

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
    pub certs: Option<Vec<CertInfo>>,
    pub key_pairs: Option<Vec<KeyPair>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CertInfo {
    pub alias: String,
    pub timestamp: u64,
    pub certificate: Cert,
    // pub raw: Vec<u8>,
    // pub cert: X509Certificate,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Cert {
    pub raw: Vec<u8>,
    pub cert: X509Certificate,
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub alias: String,
    pub timestamp: u64,
    pub encrypted_key: Vec<u8>,
    pub raw_key: Vec<u8>,
    pub cert_chain: Vec<KeyPairCert>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyPairCert {
    pub raw: Vec<u8>,
    pub cert: X509Certificate,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub password: String,
    pub skip_verify: bool,
    pub key_passwords: HashMap<String, String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            password: "changeit".to_owned(),
            skip_verify: false,
            key_passwords: HashMap::new(),
        }
    }
}

impl Store {
    pub fn parse(data: impl AsRef<[u8]>, opts: Option<Options>) -> Result<Self, Box<dyn Error>> {
        let mut buffer = BufReader::new(data.as_ref());

        let magic = read::read_u32(&mut buffer)?;
        if !magic.eq(&MAGIC) {
            return Err(format!(
                "invalid file format, expected header '{:#x?}', but got '{:#x?}'",
                MAGIC, magic
            ))?;
        }
        let version = read::read_u32(&mut buffer)?;
        if Version::from(version) == Version::Unsupported {
            return Err("unsupported version, supported only version 2".to_owned())?;
        }
        let mut keypairs: Vec<KeyPair> = vec![];
        let mut certs: Vec<CertInfo> = vec![];
        let mut opts = opts.unwrap_or_default();

        let entries = u32::from_be_bytes(read::read_u32(&mut buffer)?);
        for _ in 0..entries {
            let entry_type = EntryType::from(read::read_u32(&mut buffer)?);
            match entry_type {
                EntryType::KeyPair => keypairs.push(process_key_pair(&mut buffer, &mut opts)?),
                EntryType::Certs => certs.push(process_cert(&mut buffer)?),
            }
        }

        Ok(Store {
            certs: Some(certs),
            key_pairs: Some(keypairs),
        })
    }
}

fn process_cert<T>(data: &mut BufReader<T>) -> Result<CertInfo, Box<dyn Error>>
where
    T: Read,
{
    let alias = read::read_str(data)?;
    let timestamp = read::read_timestamp(data)?;
    // let cert_type = read_str(data)?;
    // if !cert_type.eq("X.509") {
    //     return Err(format!("not supported certificate type: {}", cert_type))?;
    // }
    // let cert_length = read_u32(data)?;
    // let cert_der = read_bytes(data, u32::from_be_bytes(cert_length) as usize)?;
    // let parsed_cert = X509Certificate::from_der(cert_der.clone())?;
    let certificate = read::read_cert(data)?;
    // let certificate = Cert {
    //     raw: cert_der,
    //     cert: parsed_cert,
    // };
    Ok(CertInfo {
        alias,
        timestamp,
        certificate,
        // raw: cert_der,
        // cert: parsed_cert,
    })
}

fn process_key_pair<T>(
    data: &mut BufReader<T>,
    opts: &mut Options,
) -> Result<KeyPair, Box<dyn Error>>
where
    T: Read,
{
    let alias = read::read_str(data)?;
    let timestamp = read::read_timestamp(data)?;
    let password = opts.key_passwords.get(&alias).unwrap_or(&opts.password);
    let key_length = read::read_u32(data)?;
    let key = read::read_bytes(data, u32::from_be_bytes(key_length) as usize)?;

    unimplemented!("key pairs")
}
