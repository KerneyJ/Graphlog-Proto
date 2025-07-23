use serde::{Deserialize, Serialize};
use clap::ValueEnum;

pub type Id = Vec<u8>;
pub type Key = (String, String);
pub type Sig = Vec<u8>;

pub trait Encodable {
    fn encode(&self) -> String;
}

pub trait Decodable<T> {
    fn decode(b64: &str) -> Option<T>;
}

// AT => ANCHOR_TYPE

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum AnchorType {
    DNS,
    EMAIL,
    PHONE,
    IPADDR,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ClaimType {
    SSHKEY,
    X509,
}

// KT => KEY_TYPE
pub static KT_ED25519: &str = "ED25519";

pub fn id_equal(id1: Id, id2: Id) -> bool {
    if id1.len() != id2.len() {
        false
    } else {
        for idx in 0..id1.len() {
            if id1.get(idx) != id2.get(idx) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(rename = "client")]
    pub client_conf: Option<ClientConfig>,
    #[serde(rename = "server")]
    pub server_conf: Option<ServerConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientConfig {
    pub log_addr: String,
    pub compiler_addr: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub addr: String,
    pub persist_path: Option<String>,
}
