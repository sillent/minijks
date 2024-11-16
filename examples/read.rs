use std::{fs::File, io::Read};

use jks;

fn main() {
    let mut buf = vec![];
    let mut f = File::open("examples/cacerts").unwrap();
    f.read_to_end(&mut buf).unwrap();
    let certs = jks::Store::parse(&buf, "".to_owned()).unwrap();
    for cert in certs.certs.unwrap() {
        println!(
            "cert alias = {}, cert cn = {:?}, and serial = {:?}",
            cert.alias,
            cert.cert.subject_common_name(),
            cert.cert.serial_number_asn1(),
        )
    }
}
