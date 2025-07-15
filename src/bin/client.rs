use chrono::{DateTime, TimeDelta, Utc};
use clap::Parser;
use curl::easy::{Easy, List};
use graphlog_proto::types::reid::Reid;
use openssl::pkey::{PKey, Private, Public};
use std::fs::File;
use std::io::Read;

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

    if let Err(why) = pubk_file.read_to_end(&mut pubk_raw) {
        panic!("Error reading public key file: {why}");
    };
    if let Err(why) = prvk_file.read_to_end(&mut prvk_raw) {
        panic!("Error reading private key file: {why}");
    };

    let pub_key: PKey<Public> = match PKey::public_key_from_pem(&pubk_raw) {
        Err(why) => panic!("Couldn't load public key from bytes, reason: {why}"),
        Ok(pub_key) => pub_key,
    };
    let prv_key: PKey<Private> = match PKey::private_key_from_pem(&prvk_raw) {
        Err(why) => panic!("Couldn't load private key from bytes, reason: {why}"),
        Ok(prv_key) => prv_key,
    };

    // if we want to print the key in pem format user below
    // let pubk_vec: Vec<u8> = pubkey.public_key_to_pem().unwrap();
    // let prvk_vec: Vec<u8> = prvkey.private_key_to_pem_pkcs8().unwrap();

    // Now + 1 month;
    let expiration: DateTime<Utc> = Utc::now() + TimeDelta::new(2628000, 0).unwrap();

    let mut reid = Reid::new_with_keys(&pub_key, &prv_key, expiration, None, None, None, true);
    println!(
        "{}\nIs valid: {}",
        reid.to_json(),
        reid.verify_sig(&pub_key)
    );

    // set Url
    let mut easy = Easy::new();
    easy.url("http://127.0.0.1:7878").unwrap();

    /* // GET request
    easy.write_function(|data| {
        println!("{data:?}");
        Ok(data.len())
    }).unwrap();
    easy.perform().unwrap();*/

    // Set Headers
    let mut headers  = List::new();
    headers.append("User-Agent: curl/8.14.1").unwrap();
    headers.append("Content-Type: application/json").unwrap();
    easy.http_headers(headers).unwrap();

    // Set POST data
    let data = r#"{"key": "something"}"#;
    // Note, this copies data into libcurl internal
    // buffer so we may want use easy.post_field_size()
    // and Read implementation - ChatGPT. Though I think
    // that they data that we are sending around is
    easy.post_fields_copy(data.as_bytes()).unwrap();

    // Perform request
    easy.perform().unwrap();

    // check response code
    let response_code = easy.response_code().unwrap();
    println!("Response code: {response_code}");
}
