use std::io::Write;
use std::fs::File;
use std::path::Path;

use openssl::pkey::{Id, PKey, Private, Public};

fn main() {
    let prv_key: PKey<Private> = PKey::generate_ed25519().unwrap();
    let pub_key_raw: Vec<u8> = prv_key.raw_public_key().unwrap();
    let pub_key: PKey<Public> = match PKey::public_key_from_raw_bytes(&pub_key_raw, Id::ED25519) {
        Err(why) => panic!("Couldn't convert raw public key into Pkey<Public>: {why}"),
        Ok(pub_key) => pub_key,
    };

    let pub_key_path = Path::new("ed25519-pub.key");
    let prv_key_path = Path::new("ed25519-prv.key");
    let puk_bytes: Vec<u8> = pub_key.public_key_to_pem().unwrap(); 
    let prk_bytes: Vec<u8> = prv_key.private_key_to_pem_pkcs8().unwrap();

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
