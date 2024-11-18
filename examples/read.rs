use std::{fs::File, io::Read};

use minijks;

fn main() {
    let mut buf = vec![];
    let mut f = File::open("examples/store-example.jks").unwrap();
    f.read_to_end(&mut buf).unwrap();
    let certs = minijks::Store::parse(&buf, None).unwrap();
    for cert in certs.certs {
        println!(
            "cert alias = {}, cert cn = {:?}, and serial = {:?}",
            cert.alias,
            cert.certificate.cert.subject_common_name(),
            cert.certificate.cert.serial_number_asn1(),
        )
    }
    for keyp in certs.key_pairs {
        println!(
            "keypair alias = {} len = {}",
            keyp.alias,
            keyp.encrypted_key.len()
        );
    }
}
