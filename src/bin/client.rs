use std::fs::File;
use std::io::Read;

use clap::Parser;

use openssl::pkey::{PKey, Private, Public};


#[derive(Parser)]
struct Cli {
    pubk_path: std::path::PathBuf,
    prvk_path: std::path::PathBuf,
}

fn main() {
    let args = Cli::parse();

    let mut pubk_file = match File::open(args.pubk_path) {
        Err(why) => panic!("Couldn't open public key file, reason: {why}"),
        Ok(pubk_file) => pubk_file,
    };

    let mut prvk_file = match File::open(args.prvk_path) {
        Err(why) => panic!("Couldn't open public key file, reason: {why}"),
        Ok(prvk_file) => prvk_file,
    };

    let mut pubk_raw: Vec<u8> = Vec::new();
    let mut prvk_raw: Vec<u8> = Vec::new();

    if let Err(why) = pubk_file.read_to_end(&mut pubk_raw){
       panic!("Error reading public key file: {why}");
    };
    if let Err(why) = prvk_file.read_to_end(&mut prvk_raw) {
        panic!("Error reading private key file: {why}");
    };

    let pubkey: PKey<Public> = match PKey::public_key_from_pem(&pubk_raw) {
        Err(why) => panic!("Couldn't load public key from bytes, reason: {why}"),
        Ok(pubkey) => pubkey,
    };
    let prvkey: PKey<Private> = match PKey::private_key_from_pem(&prvk_raw) {
        Err(why) => panic!("Couldn't load private key from bytes, reason: {why}"),
        Ok(prvkey) => prvkey,
    };

    let pubk_vec: Vec<u8> = pubkey.public_key_to_pem().unwrap();
    let prvk_vec: Vec<u8> = prvkey.private_key_to_pem_pkcs8().unwrap();

    println!("{:?}", std::str::from_utf8(pubk_vec.as_slice()).unwrap());
    println!("{:?}", std::str::from_utf8(prvk_vec.as_slice()).unwrap());
}
