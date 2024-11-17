use super::Cert;
use std::error::Error;
use std::io::{BufReader, Read, Seek, SeekFrom};
use x509_certificate::certificate::X509Certificate;
pub(crate) fn read_cert<T>(data: &mut BufReader<T>) -> Result<Cert, Box<dyn Error>>
where
    T: Read,
{
    let cert_type = read_str(data)?;
    if !cert_type.eq("X.509") {
        return Err(format!("not supported certificate type: {}", cert_type))?;
    }
    let cert_length = read_u32(data)?;
    let cert_der = read_bytes(data, u32::from_be_bytes(cert_length) as usize)?;
    let parsed_cert = X509Certificate::from_der(cert_der.clone())?;
    Ok(Cert {
        raw: cert_der,
        cert: parsed_cert,
    })
}

pub(crate) fn read_bytes<T>(data: &mut BufReader<T>, len: usize) -> Result<Vec<u8>, String>
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

pub(crate) fn read_u16<T>(data: &mut BufReader<T>) -> Result<[u8; 2], String>
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

pub(crate) fn read_u32<T>(data: &mut BufReader<T>) -> Result<[u8; 4], String>
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

pub(crate) fn read_u64<T>(data: &mut BufReader<T>) -> Result<[u8; 8], String>
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

pub(crate) fn read_str<T>(data: &mut BufReader<T>) -> Result<String, String>
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

pub(crate) fn read_timestamp<T>(data: &mut BufReader<T>) -> Result<u64, String>
where
    T: Read,
{
    let timestamp = read_u64(data)?;
    Ok(u64::from_be_bytes(timestamp))
}

#[cfg(test)]
mod tests {
    use crate::MAGIC;
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
