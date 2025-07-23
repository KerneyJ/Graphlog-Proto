use chrono::{DateTime, NaiveDateTime, Utc};
use clap::{Parser, Subcommand};
use curl::easy::{Easy, List};
use dialoguer::theme::ColorfulTheme;
use dialoguer::Input;
use graphlog_proto::types::common::{AnchorType, ClaimType, ClientConfig, Config, Encodable};
use graphlog_proto::types::reid::Reid;
use openssl::pkey::{Id, PKey, Private, Public};
use std::{
    env, fs,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(name = "graphlogo prototype client", version = "1.0")]
#[command(about = "prototype client cli for interacting with graphlog")]
struct Cli {
    // Figure out things that we would do and put those options here
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Publish current reid to log
    Publish {
        #[arg(short, long)]
        log_addr: Option<String>,
    },
    AppendAnchor {
        #[arg(value_enum, short, long)]
        anchor_type: AnchorType,
        #[arg(short, long)]
        anchor_value: String,
    },
    AppendClaim {
        #[arg(short, long)]
        claim_type: ClaimType,
        #[arg(short, long)]
        claim_value: String,
    },
}

fn main() {
    let cli: Cli = Cli::parse();
    let home_dir: PathBuf = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE")) // windows
        .map(PathBuf::from)
        .expect("Could not determine home directory");

    let graphlog_dir = home_dir.join(".graphlog");

    if graphlog_dir.exists() && graphlog_dir.is_dir() {
        // Load from the config file
        let pubk_path: PathBuf = graphlog_dir.join("graphlog-pub.key");
        let prvk_path: PathBuf = graphlog_dir.join("graphlog-prv.key");
        let conf_path: PathBuf = graphlog_dir.join("graphlog.toml");

        let (pub_key, prv_key) = extract_keys_from_file(pubk_path, prvk_path);
        let toml_str = fs::read_to_string(conf_path).unwrap();
        let conf: Config = toml::from_str(&toml_str).unwrap();
        parse_and_execute(pub_key, prv_key, conf, cli);
    } else {
        // Create key and config stuff
        if let Err(why) = fs::create_dir_all(&graphlog_dir) {
            panic!("Directory does not exist and failed to create: {why}");
        }
        let (pub_key, prv_key, conf) = config_init(&graphlog_dir);
        parse_and_execute(pub_key, prv_key, conf, cli);
    }
}

// Initial config functions
fn config_init(graphlog_dir: &Path) -> (PKey<Public>, PKey<Private>, Config) {
    // create keys
    let (pub_key, prv_key) = gen_keys(graphlog_dir);
    // Input for what will be placed in the config file
    let config = gen_config_file(graphlog_dir);
    (pub_key, prv_key, config)
}

fn gen_keys(graphlog_dir: &Path) -> (PKey<Public>, PKey<Private>) {
    let prv_key: PKey<Private> = PKey::generate_ed25519().unwrap();
    let pub_key_raw: Vec<u8> = prv_key.raw_public_key().unwrap();
    let pub_key: PKey<Public> = match PKey::public_key_from_raw_bytes(&pub_key_raw, Id::ED25519) {
        Err(why) => panic!("Couldn't convert raw public key into Pkey<Public>: {why}"),
        Ok(pub_key) => pub_key,
    };

    let pub_key_path: PathBuf = graphlog_dir.join("graphlog-pub.key");
    let prv_key_path: PathBuf = graphlog_dir.join("graphlog-prv.key");
    let puk_bytes: Vec<u8> = pub_key.public_key_to_pem().unwrap();
    let prk_bytes: Vec<u8> = prv_key.private_key_to_pem_pkcs8().unwrap();

    let mut pub_file = match File::create(&pub_key_path) {
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
    (pub_key, prv_key)
}

fn gen_config_file(graphlog_dir: &Path) -> Config {
    let config_path = graphlog_dir.join("graphlog.toml");
    let log_addr: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter a log address")
        .default(String::from("127.0.0.1:7878"))
        .interact_text()
        .unwrap();

    let compiler_addr: Option<String> = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter a Compiler address")
        .allow_empty(true)
        .interact_text()
        .ok();

    let config = Config {
        client_conf: Some(ClientConfig {
            log_addr,
            compiler_addr,
        }),
        server_conf: None,
    };

    let toml_string: String = toml::to_string_pretty(&config).unwrap();
    if let Err(why) = fs::write(config_path, toml_string) {
        println!("Error writing generated config to file: {why}");
    }
    config
}

fn extract_keys_from_file(pubk_path: PathBuf, prvk_path: PathBuf) -> (PKey<Public>, PKey<Private>) {
    let mut pubk_file = match File::open(pubk_path) {
        Err(why) => panic!("Couldn't open public key file, reason: {why}"),
        Ok(pubk_file) => pubk_file,
    };

    let mut prvk_file = match File::open(prvk_path) {
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

// Business functions that do stuff
fn parse_and_execute(pub_key: PKey<Public>, prv_key: PKey<Private>, conf: Config, cli: Cli) {
    match cli.command {
        // None => { println!("No options passed"); },
        Commands::Publish { log_addr } => {
        },
        Commands::AppendAnchor {
            anchor_type,
            anchor_value,
        } => {
        },
        Commands::AppendClaim {
            claim_type,
            claim_value,
        } => {
        },
    }
}

fn create_reid_from_key(pub_key: PKey<Public>, prv_key: PKey<Private>) -> Option<Reid> {
    let input: String = Input::new()
        .with_prompt("Enter an expiration date")
        .default(String::from("2026-07-16 12:00"))
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
        &pub_key, &prv_key, expiration, None, None, None, false,
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
/*
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
                r.append_claim(claim_type, claim_value);
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
*/
/*
fn _get_claim() -> Option<(String, Key)> {
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
                Err(why) => {
                    println!("Couldn't open public key file, reason: {why}");
                    return None;
                }
                Ok(pubk_file) => pubk_file,
            };

            let mut pubk_raw: Vec<u8> = Vec::new();
            if let Err(why) = pubk_file.read_to_end(&mut pubk_raw) {
                println!("Error reading public key file: {why}");
                return None;
            };

            let pubk_str: String = match String::from_utf8(pubk_raw) {
                Err(why) => {
                    println!("Error converting file to utf8: {why}");
                    return None;
                }
                Ok(pubk_str) => pubk_str,
            };
            let pubk_str = pubk_str.replace(['\n', '\r'], "");
            Some((
                CLMT_SSHKEY.to_string(),
                (KT_ED25519.to_string(), pubk_str),
                // TODO, currently only one key type(ED25519) is
                // supported so I have hard coded the key type, in future
                // need to make an option to select key type here
            ))
        }
        1 => {
            println!("Not implemented!");
            None
        }
        _ => None,
    }
}
*/
/*
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
*/
fn post_reid(log_addr: String, reid: &Reid, pem_str: String) {
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
    let data = format!(
        "{{\"reid\": \"{}\", \"pubk\": \"{}\"}}",
        reid.clone().encode(),
        pem_str
    );
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
        println!("{}", reid.unwrap());
        Ok(data.len())
    })
    .unwrap();
    easy.perform().unwrap();
}

fn look_up_reid(log_addr: String) {
    let id_b64: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter base64 encoded Id")
        .interact()
        .unwrap();

    // set Url
    let mut easy = Easy::new();
    let endpoint: String = format!("http://{log_addr}/look_up");
    easy.url(&endpoint).unwrap();

    // Set Headers
    let mut headers = List::new();
    headers.append("User-Agent: curl/8.14.1").unwrap();
    headers.append("Content-Type: application/json").unwrap();
    easy.http_headers(headers).unwrap();

    // Set POST data
    let data = format!("{{\"id_b64\": \"{id_b64}\"}}");
    // Note, this copies data into libcurl internal
    // buffer so we may want use easy.post_field_size()
    // and Read implementation - ChatGPT. Though I think
    // that they data that we are sending around is
    easy.post_fields_copy(data.as_bytes()).unwrap();

    easy.write_function(|data| {
        let response: Vec<String> = _format_get(data);
        let reid = Reid::new_from_header(response);
        println!("{}", reid.unwrap());
        Ok(data.len())
    })
    .unwrap();
    // Perform request
    easy.perform().unwrap();
}

fn _format_get(raw: &[u8]) -> Vec<String> {
    let raw_vec: Vec<u8> = raw.to_vec();
    let raw_str: String = String::from_utf8(raw_vec).unwrap();
    raw_str.split("\r\n\n").map(|s| s.to_string()).collect()
}
