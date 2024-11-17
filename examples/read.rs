use std::{fs::File, io::Read};

use minijks;

fn main() {
    let mut buf = vec![];
    let mut f = File::open("examples/file.jks").unwrap();
    f.read_to_end(&mut buf).unwrap();
    let certs = minijks::Store::parse(&buf, None).unwrap();
    for cert in certs.certs.unwrap() {
        println!(
            "cert alias = {}, cert cn = {:?}, and serial = {:?}",
            cert.alias,
            cert.certificate.cert.subject_common_name(),
            cert.certificate.cert.serial_number_asn1(),
        )
    }
}
