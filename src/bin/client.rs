use chrono::{DateTime, NaiveDateTime, Utc};
use clap::Parser;
use curl::easy::{Easy, List};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Input, Select};
use graphlog_proto::types::common::*;
use graphlog_proto::types::reid::Reid;
use openssl::pkey::{PKey, Private, Public};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "graphlogo prototype client", version = "1.0")]
#[command(about = "prototype client cli for interacting with graphlog")]
struct Cli {
    pubk_path: std::path::PathBuf,
    prvk_path: std::path::PathBuf,
}

fn main() {
    let args: Cli = Cli::parse();

    let (pub_key, prv_key) = extract_keys_from_file(args);
    let cli_options = &[
        "Create User Reid",
        "Update User Reid",
        "Post User Reid to Log",
        "Get Tail Reid",
        "Look Up Id",
        "Display User Reid",
        "Exit",
    ];
    let mut reid: Option<Reid> = None;
    let mut log_addr: Option<String> = None;
    loop {
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("GraphLog Prototype")
            .items(cli_options)
            .interact()
            .unwrap();
        match selection {
            0 => {
                // Create Reid
                let r: &mut Option<Reid> = &mut reid;
                if r.is_none() {
                    *r = create_reid_from_key(pub_key.clone(), prv_key.clone());
                } else {
                    println!("Reid already created");
                }
            }
            1 => {
                // Update Reid
                let r: &mut Option<Reid> = &mut reid;
                if r.is_none() {
                    println!("Reid not yet created");
                    continue;
                }
                *r = update_reid(r.take());
            }
            2 => {
                // Post Reid to log
                let l: &mut Option<String> = &mut log_addr;
                if let Some(r) = &reid {
                    if l.is_none() {
                        let input: String = Input::new()
                            .with_prompt("Enter the Log's ip address/domain")
                            .interact_text()
                            .unwrap();
                        *l = Some(input);
                        post_reid(l.clone().unwrap(), r);
                    } else {
                        post_reid(l.clone().unwrap(), r);
                    }
                } else {
                    println!("Reid not yet created");
                    continue;
                }
            }
            3 => {
                // Get tail Reid
                if let Some(l) = &log_addr {
                    get_tail(l.to_string())
                } else {
                    let input: String = Input::new()
                        .with_prompt("Enter the Log's ip address/domain")
                        .interact_text()
                        .unwrap();
                    let l: &mut Option<String> = &mut log_addr;
                    *l = Some(input);
                    get_tail(l.as_ref().unwrap().to_string())
                }
            }
            4 => look_up_reid(),
            5 => display_reid(),
            _ => break,
        }
    }

    /*let mut reid = Reid::new_with_keys(&pub_key, &prv_key, expiration, None, None, None, true);
    println!(
        "{}\nIs valid: {}",
        reid.to_json(),
        reid.verify_sig(&pub_key)
    );*/
}

fn extract_keys_from_file(args: Cli) -> (PKey<Public>, PKey<Private>) {
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
    (pub_key, prv_key)
}

fn create_reid_from_key(pub_key: PKey<Public>, prv_key: PKey<Private>) -> Option<Reid> {
    let input: String = Input::new()
        .with_prompt("Enter an expiration date(e.g. 2025-07-16 15:00")
        .interact_text()
        .unwrap();
    let expiration: DateTime<Utc> = match _parse_datetime(&input) {
        Some(dt) => dt.with_timezone(&Utc),
        None => {
            println!("Failed to read date input");
            return None;
        }
    };

    Some(Reid::new_with_keys(
        &pub_key, &prv_key, expiration, None, None, None, true,
    ))
}

fn _parse_datetime(input: &str) -> Option<DateTime<Utc>> {
    let formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%Y-%m-%dT%H:%M:%SZ", // RFC3339 without timezone offset
    ];

    for format in formats {
        if let Ok(naive_dt) = NaiveDateTime::parse_from_str(input, format) {
            return Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
        }
    }

    None
}

fn update_reid(reid: Option<Reid>) -> Option<Reid> {
    // In this function I don't understand why I need clones
    // on the next line and at all return statements
    let r: &mut Reid = &mut reid.unwrap().clone();
    let sub_options = &["Append Claim", "Append Anchor"];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("GraphLog Prototype")
        .items(sub_options)
        .interact()
        .unwrap();
    match selection {
        0 => {
            // Append claim
            if let Some((claim_type, claim_value)) = _get_claim() {
                r.append_claim(claim_type, claim_value.into_bytes());
                Some(r.clone())
            } else {
                println!("Getting claim type failed");
                Some(r.clone())
            }
        }
        1 => {
            // Append anchor
            if let Some((anchor_type, anchor_value)) = _get_anchor() {
                r.append_anchor(anchor_type, anchor_value);
                Some(r.clone())
            } else {
                println!("Getting anchor type failed");
                Some(r.clone())
            }
        }
        _ => None,
    }
}

fn _get_claim() -> Option<(String, String)> {
    let sub_options = &[CLMT_SSHKEY, CLMT_X509];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose a key type to claim")
        .items(sub_options)
        .interact()
        .unwrap();
    match selection {
        0 => {
            let ssh_pub_key_filename: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("SSH Public Key Path")
                .interact()
                .unwrap();
            let ssh_pub_key_path = match PathBuf::from_str(&ssh_pub_key_filename) {
                Err(why) => {
                    println!("Failed to read ssh pub key file: {why}");
                    return None;
                }
                Ok(path) => path,
            };
            let mut pubk_file = match File::open(ssh_pub_key_path) {
                Err(why) => panic!("Couldn't open public key file, reason: {why}"),
                Ok(pubk_file) => pubk_file,
            };

            let mut pubk_raw: Vec<u8> = Vec::new();
            if let Err(why) = pubk_file.read_to_end(&mut pubk_raw) {
                panic!("Error reading public key file: {why}");
            };
            Some((
                CLMT_SSHKEY.to_string(),
                String::from_utf8(pubk_raw).unwrap(),
            ))
        }
        1 => {
            println!("Not implemented!");
            None
        }
        _ => None,
    }
}

fn _get_anchor() -> Option<(String, String)> {
    let sub_options = &[AT_IPADDR, AT_DNS, AT_EMAIL, AT_PHONE];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an Anchor type to root your claims")
        .items(sub_options)
        .interact()
        .unwrap();
    match selection {
        0 => {
            let anchor: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter ip address")
                .interact()
                .unwrap();
            Some((AT_IPADDR.to_string(), anchor))
        }
        1 => {
            let anchor: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter domain name")
                .interact()
                .unwrap();
            Some((AT_DNS.to_string(), anchor))
        }
        2 => {
            let anchor: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter email address")
                .interact()
                .unwrap();
            Some((AT_EMAIL.to_string(), anchor))
        }
        3 => {
            let anchor: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter phone number")
                .interact()
                .unwrap();
            Some((AT_PHONE.to_string(), anchor))
        }
        _ => None,
    }
}

fn post_reid(log_addr: String, reid: &Reid) {
    // set Url
    let mut easy = Easy::new();
    let endpoint: String = format!("http://{log_addr}");
    easy.url(&endpoint).unwrap();

    // Set Headers
    let mut headers = List::new();
    headers.append("User-Agent: curl/8.14.1").unwrap();
    headers.append("Content-Type: application/json").unwrap();
    easy.http_headers(headers).unwrap();

    // Set POST data
    let data = format!("{{\"reid\": \"{}\"}}", reid.clone().encode());
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

fn get_tail(log_addr: String) {
    // Set Url
    let mut easy = Easy::new();
    let endpoint: String = format!("http://{log_addr}/tail");
    easy.url(&endpoint).unwrap();

    // Set Headers
    let mut headers = List::new();
    headers.append("User-Agent: curl/8.14.1").unwrap();
    headers.append("Content-Type: application/json").unwrap();
    easy.http_headers(headers).unwrap();

    easy.write_function(|data| {
        let response: Vec<String> = _format_get(data);
        let reid = Reid::new_from_header(response);
        println!("{reid:?}");
        Ok(data.len())
    })
    .unwrap();
    easy.perform().unwrap();
}

fn look_up_reid() {}

fn _format_get(raw: &[u8]) -> Vec<String> {
    let raw_vec: Vec<u8> = raw.to_vec();
    let raw_str: String = String::from_utf8(raw_vec).unwrap();
    raw_str.split("\r\n\n").map(|s| s.to_string()).collect()
}

fn display_reid() {}
