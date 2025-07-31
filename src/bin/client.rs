use chrono::{DateTime, NaiveDateTime, Utc};
use clap::{CommandFactory, Parser, Subcommand};
use dialoguer::theme::ColorfulTheme;
use dialoguer::Input;
use graphlog_proto::types::common::{AnchorType, ClaimType, ClientConfig, Config, Key, KeyType};
use graphlog_proto::types::reid::Reid;
use graphlog_proto::utils::http_server::ReidMessage;
use openssl::pkey::{Id, PKey, Private, Public};
use reqwest::{Client, StatusCode};
use std::panic;
use std::{
    env, fs,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(name = "graphlogo prototype client", version = "1.0")]
#[command(about = "prototype client cli for interacting with graphlog")]
#[command(arg_required_else_help = true)]
struct Cli {
    // Figure out things that we would do and put those options here
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Publish current reid to log
    Publish {
        #[arg(short, long)]
        log_addr: Option<String>,
    },
    /// Append a claim to current reid
    AppendClaim {
        #[arg(value_enum, long)]
        claim_type: ClaimType,
        #[arg(long)]
        claim_key_type: KeyType,
        #[arg(long)]
        claim_key_path: PathBuf,
        #[arg(short, long)]
        publish: Option<bool>,
    },
    /// Append an anchor to current reid
    AppendAnchor {
        #[arg(value_enum, long)]
        anchor_type: AnchorType,
        #[arg(long)]
        anchor_value: String,
        #[arg(short, long)]
        publish: Option<bool>,
    },
    /// Look up reid using base64 id
    LookupReid {
        #[arg(short, long)]
        id: String,
        #[arg(short, long)]
        log_addr: Option<String>,
    },
    /// Get the last entry of a log
    GetTail {
        #[arg(short, long)]
        log_addr: Option<String>,
    },
    /// Mark Reid entry as revoked
    Revoke {
        #[arg(short, long)]
        log_addr: Option<String>,
    },
    // TODO add tail_num
}

#[tokio::main]
async fn main() {
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
        let config: Config = match toml::from_str(&toml_str) {
            Err(why) => panic!("Error loading toml: {why}"),
            Ok(config) => config,
        };
        parse_and_execute(pub_key, prv_key, config, cli).await;
    } else {
        // Create key and config stuff
        if let Err(why) = fs::create_dir_all(&graphlog_dir) {
            panic!("Directory does not exist and failed to create: {why}");
        }
        let (pub_key, prv_key, conf) = config_init(&graphlog_dir);
        parse_and_execute(pub_key, prv_key, conf, cli).await;
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
        Ok(_) => println!("Wrote public key to file"),
    }

    let mut prv_file = match File::create(prv_key_path) {
        Err(why) => panic!("couldn't create {}: {}", pub_key_path.display(), why),
        Ok(prv_file) => prv_file,
    };

    match prv_file.write_all(&prk_bytes) {
        Err(why) => panic!("couldn't write to public key: {why}"),
        Ok(_) => println!("Wrote private key to file"),
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
    let expiration_str: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter an expiration date")
        .default(String::from("2026-07-16 12:00"))
        .interact_text()
        .unwrap();
    let expiration: DateTime<Utc> = match _parse_datetime(&expiration_str) {
        Some(dt) => dt.with_timezone(&Utc),
        None => {
            panic!("Failed to read date input");
        }
    };

    let config = Config {
        client_conf: Some(ClientConfig {
            log_addr,
            compiler_addr,
            expiration,
            claims: None,
            anchors: None,
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
    (
        load_public_key_from_file(pubk_path),
        load_private_key_from_file(prvk_path),
    )
}

fn load_public_key_from_file(pubk_path: PathBuf) -> PKey<Public> {
    let mut pubk_file = match File::open(pubk_path) {
        Err(why) => panic!("Couldn't open public key file, reason: {why}"),
        Ok(pubk_file) => pubk_file,
    };
    let mut pubk_raw: Vec<u8> = Vec::new();
    if let Err(why) = pubk_file.read_to_end(&mut pubk_raw) {
        panic!("Error reading public key file: {why}");
    };
    match PKey::public_key_from_pem(&pubk_raw) {
        Err(why) => panic!("Couldn't load public key from bytes, reason: {why}"),
        Ok(pub_key) => pub_key,
    }
}

fn load_private_key_from_file(prvk_path: PathBuf) -> PKey<Private> {
    let mut prvk_file = match File::open(prvk_path) {
        Err(why) => panic!("Couldn't open public key file, reason: {why}"),
        Ok(prvk_file) => prvk_file,
    };
    let mut prvk_raw: Vec<u8> = Vec::new();
    if let Err(why) = prvk_file.read_to_end(&mut prvk_raw) {
        panic!("Error reading private key file: {why}");
    };

    match PKey::private_key_from_pem(&prvk_raw) {
        Err(why) => panic!("Couldn't load private key from bytes, reason: {why}"),
        Ok(prv_key) => prv_key,
    }
}

// Business functions that do stuff
async fn parse_and_execute(
    pub_key: PKey<Public>,
    prv_key: PKey<Private>,
    config: Config,
    cli: Cli,
) {
    // TODO eventually load all of the reid anchor and claims from the config file here
    let client_config: ClientConfig = config.client_conf.unwrap();
    let expiration: DateTime<Utc> = client_config.expiration;
    let mut reid: Reid =
        Reid::new_with_keys(&pub_key, &prv_key, expiration, None, None, None, false);
    match cli.command {
        Some(Commands::Publish { log_addr }) => {
            // get pem_str
            let pem_vec: Vec<u8> = match pub_key.public_key_to_pem() {
                Err(why) => panic!("Could not convert pub_key to pem format: {why}"),
                Ok(vec) => vec,
            };
            let pem_str: String = match String::from_utf8(pem_vec) {
                Err(why) => panic!("Couldn't convert pem vec to string: {why}"),
                Ok(str) => str,
            };

            if let Some(log_addr) = log_addr {
                publish_reid(log_addr, reid, pem_str).await;
            } else {
                publish_reid(client_config.log_addr, reid, pem_str).await;
            }
        }
        Some(Commands::AppendClaim {
            claim_type,
            claim_key_type,
            claim_key_path,
            publish,
        }) => {
            // get pem_str
            let pem_vec: Vec<u8> = match pub_key.public_key_to_pem() {
                Err(why) => panic!("Could not convert pub_key to pem format: {why}"),
                Ok(vec) => vec,
            };
            let pem_str: String = match String::from_utf8(pem_vec) {
                Err(why) => panic!("Couldn't convert pem vec to string: {why}"),
                Ok(str) => str,
            };

            let claim_key_str: String = match claim_key_type {
                KeyType::ED25519 => {
                    let claim_pkey: PKey<Public> = load_public_key_from_file(claim_key_path);
                    let claim_key_vec: Vec<u8> = match claim_pkey.public_key_to_pem() {
                        Err(why) => panic!("Could not convert pub_key to pem format: {why}"),
                        Ok(vec) => vec,
                    };
                    match String::from_utf8(claim_key_vec) {
                        Err(why) => panic!("Couldn't convert pem vec to string: {why}"),
                        Ok(str) => str,
                    }
                }
                KeyType::CHACHA20POLY1305 => {
                    let mut pubk_file = match File::open(claim_key_path) {
                        Err(why) => panic!("Couldn't open public key file, reason: {why}"),
                        Ok(pubk_file) => pubk_file,
                    };
                    let mut pubk_raw: Vec<u8> = Vec::new();
                    if let Err(why) = pubk_file.read_to_end(&mut pubk_raw) {
                        panic!("Error reading public key file: {why}");
                    };
                    match String::from_utf8(pubk_raw) {
                        Err(why) => panic!("Couldn't convert read key to string: {why}"),
                        Ok(str) => str,
                    }
                }
            };

            let claim_value: Key = (claim_key_type, claim_key_str);
            append_claim(
                claim_type,
                claim_value,
                reid,
                client_config,
                publish.unwrap_or_default(),
                pem_str,
            )
            .await;
        }
        Some(Commands::AppendAnchor {
            anchor_type,
            anchor_value,
            publish,
        }) => {
            let pem_vec: Vec<u8> = match pub_key.public_key_to_pem() {
                Err(why) => panic!("Could not convert pub_key to pem format: {why}"),
                Ok(vec) => vec,
            };
            let pem_str: String = match String::from_utf8(pem_vec) {
                Err(why) => panic!("Couldn't convert pem vec to string: {why}"),
                Ok(str) => str,
            };
            append_anchor(
                anchor_type,
                anchor_value,
                reid,
                client_config,
                publish.unwrap_or_default(),
                pem_str,
            )
            .await;
        }
        Some(Commands::LookupReid { id, log_addr }) => {
            if let Some(log_addr) = log_addr {
                look_up_reid(log_addr, id).await;
            } else {
                look_up_reid(client_config.log_addr, id).await;
            }
        }
        Some(Commands::GetTail { log_addr }) => {
            if let Some(log_addr) = log_addr {
                get_tail(log_addr).await;
            } else {
                get_tail(client_config.log_addr).await;
            }
        }
        Some(Commands::Revoke { log_addr }) => {
            reid.revoke();
            let pem_vec: Vec<u8> = match pub_key.public_key_to_pem() {
                Err(why) => panic!("Could not convert pub_key to pem format: {why}"),
                Ok(vec) => vec,
            };
            let pem_str: String = match String::from_utf8(pem_vec) {
                Err(why) => panic!("Couldn't convert pem vec to string: {why}"),
                Ok(str) => str,
            };

            if let Some(log_addr) = log_addr {
                publish_reid(log_addr, reid, pem_str).await
            } else {
                publish_reid(client_config.log_addr, reid, pem_str).await
            }
        }
        None => {
            Cli::command().print_help().unwrap();
            panic!("Incorrect arguments");
        }
    }
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

async fn append_claim(
    claim_type: ClaimType,
    claim_value: Key,
    mut reid: Reid,
    client_config: ClientConfig,
    publish: bool,
    pem_str: String,
) {
    reid.append_claim(claim_type.clone(), claim_value.clone());
    let log_addr: String = client_config.log_addr.clone();
    client_config
        .claims
        .unwrap()
        .push((claim_type, claim_value));
    if publish {
        publish_reid(log_addr, reid, pem_str).await;
    }
}

async fn append_anchor(
    anchor_type: AnchorType,
    anchor_value: String,
    mut reid: Reid,
    client_config: ClientConfig,
    publish: bool,
    pem_str: String,
) {
    reid.append_anchor(anchor_type.clone(), anchor_value.clone());
    let log_addr: String = client_config.log_addr.clone();
    client_config
        .anchors
        .unwrap()
        .push((anchor_type, anchor_value));

    if publish {
        publish_reid(log_addr, reid, pem_str).await;
    }
}

async fn publish_reid(log_addr: String, reid: Reid, pem_str: String) {
    let client = Client::new();
    let endpoint: String = format!("http://{log_addr}/publish");
    let res = client
        .post(endpoint)
        .json(&ReidMessage {
            reid,
            pub_key: pem_str,
        })
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::OK => println!("Successful append reid"),
        StatusCode::NOT_ACCEPTABLE => println!("Log server could not verify certificate"),
        code => println!("Unexpected status code: {code}"),
    }
}

async fn get_tail(log_addr: String) {
    let client = Client::new();
    let endpoint: String = format!("http://{log_addr}/tail");
    let res = client.get(endpoint).send().await.unwrap();

    let status: StatusCode = res.status();
    if status.is_success() {
        match res.json::<Reid>().await {
            Ok(reid) => {
                println!("Received reid: {reid}");
            }
            Err(why) => {
                println!("Failed to parse json: {why}");
            }
        };
    } else {
        println!("Get tail request failed with status {status}");
    }
}

async fn look_up_reid(log_addr: String, id_b64: String) {
    let client = Client::new();
    let endpoint: String = format!("http://{log_addr}/{id_b64}");
    let res = client.get(endpoint).send().await.unwrap();

    let status: StatusCode = res.status();

    if status.is_success() {
        match res.json::<Reid>().await {
            Ok(reid) => {
                println!("Received reid: {reid}");
            }
            Err(why) => {
                println!("Failed to parse json: {why}");
            }
        };
    } else {
        println!("Look up of reid {id_b64} failed: {status}");
    }
}
