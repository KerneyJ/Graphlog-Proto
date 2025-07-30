use std::fmt;

use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

pub type Id = Vec<u8>;
pub type Key = (KeyType, String);
pub type Sig = Vec<u8>;

pub trait Encodable {
    fn encode(&self) -> String;
}

pub trait Decodable<T> {
    fn decode(b64: &str) -> Option<T>;
}

#[repr(u8)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ClaimType {
    SSHKEY,
    X509,
    WGKEY, // Wireguard Key
}

impl fmt::Display for ClaimType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::SSHKEY => {
                writeln!(f, "SSH Key").unwrap();
            }
            Self::X509 => {
                writeln!(f, "X.509").unwrap();
            }
            Self::WGKEY => {
                writeln!(f, "Wireguard Key").unwrap();
            }
        }
        Ok(())
    }
}

#[repr(u8)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum KeyType {
    ED25519,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::ED25519 => {
                writeln!(f, "ED25519").unwrap();
            }
        };
        Ok(())
    }
}

#[repr(u8)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum AnchorType {
    DNS,
    EMAIL,
    PHONE,
    IPADDR,
}

impl fmt::Display for AnchorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::DNS => {
                writeln!(f, "DNS Entry").unwrap();
            }
            Self::EMAIL => {
                writeln!(f, "Email").unwrap();
            }
            Self::PHONE => {
                writeln!(f, "Phone").unwrap();
            }
            Self::IPADDR => {
                writeln!(f, "Ip Addr").unwrap();
            }
        }
        Ok(())
    }
}

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
    pub expiration: DateTime<Utc>,
    pub claims: Option<Vec<(ClaimType, Key)>>,
    pub anchors: Option<Vec<(AnchorType, String)>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub addr: String,
    pub persist_path: Option<String>,
}
