use std::io::Write;
use std::fs::File;
use std::path::Path;

use openssl::pkey::PKey;
use openssl::rsa::Rsa;

fn main() {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let pub_key_path = Path::new("rsa-pub.key");
    let prv_key_path = Path::new("rsa-prv.key");
    let puk_bytes: Vec<u8> = pkey.public_key_to_pem().unwrap();
    let prk_bytes: Vec<u8> = pkey.private_key_to_pem_pkcs8().unwrap();

    let mut pub_file = match File::create(pub_key_path) {
        Err(why) => panic!("couldn't create {}: {}", pub_key_path.display(), why),
        Ok(pub_file) => pub_file,
    };

    match pub_file.write_all(&puk_bytes) {
        Err(why) => panic!("couldn't write to public key: {why}"),
        Ok(_) => println!("successfully wrote to public key"),
    }

    let mut prv_file = match File::create(prv_key_path) {
        Err(why) => panic!("couldn't create {}: {}", pub_key_path.display(), why),
        Ok(prv_file) => prv_file,
    };

    match prv_file.write_all(&prk_bytes) {
        Err(why) => panic!("couldn't write to public key: {why}"),
        Ok(_) => println!("successfully wrote to public key"),
    }
}
