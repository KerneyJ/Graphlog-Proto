use crate::types::common::KeyType;

use super::common::{Encodable, Decodable, Id, Key, Sig, AnchorType, ClaimType};
use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use openssl::base64::{decode_block, encode_block};
use openssl::sign::Verifier;
use openssl::{
    error::ErrorStack,
    hash::{Hasher, MessageDigest},
    pkey::{PKey, Private, Public},
    sign::Signer,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Reid {
    pub id: Id,           // Hash of public key
    pow: Option<Vec<u8>>, // proof of work, optionally required by the log
    #[serde(with = "ts_seconds")]
    expiration: DateTime<Utc>, // datetime wherein which the record expires
    sig: Sig,             // signature
    claims: Option<Vec<(ClaimType, Key)>>,
    anchors: Option<Vec<(AnchorType, String)>>,
    revoked: bool,
}

impl Reid {
    pub fn new(
        id: Id,
        pow: Option<Vec<u8>>,
        expiration: DateTime<Utc>,
        sig: Sig,
        claims: Option<Vec<(ClaimType, Key)>>,
        anchors: Option<Vec<(AnchorType, String)>>,
        revoked: bool,
    ) -> Self {
        Self {
            id,
            pow,
            expiration,
            sig,
            claims,
            anchors,
            revoked,
        }
    }

    pub fn new_with_keys(
        pub_key: &PKey<Public>,
        prv_key: &PKey<Private>,
        expiration: DateTime<Utc>,
        pow: Option<Vec<u8>>,
        claims: Option<Vec<(ClaimType, Key)>>,
        anchors: Option<Vec<(AnchorType, String)>>,
        revoked: bool,
    ) -> Self {
        // Generate ID which is just hash(public key)
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        let pub_key_raw: Vec<u8> = match pub_key.raw_public_key() {
            Err(why) => {
                panic!("Couldn't convert public key into raw bytes using raw_public_key: {why}")
            }
            Ok(pub_key_raw) => pub_key_raw,
        };
        if let Err(why) = hasher.update(&pub_key_raw) {
            panic!("Hasher updated failed: {why}");
        }

        let id: Id = match hasher.finish() {
            Err(why) => panic!("Hashing public key failed: {why}"),
            Ok(id) => id.to_vec(),
        };

        let sig: Sig = match Reid::sign_reid_with_args(prv_key, &id, expiration, &claims, &anchors)
        {
            Err(why) => panic!("Signing Reid failed: {why}"),
            Ok(sig) => sig,
        };

        Self {
            id,
            pow,
            expiration,
            sig,
            claims,
            anchors,
            revoked,
        }
    }
/* TODO REMOVE
    pub fn new_from_header(header: Vec<String>) -> Option<Self> {
        let content_type: String = match header.iter().find(|s| s.contains("Content-Type: ")) {
            Some(found) => found.strip_prefix("Content-Type: ").unwrap().to_string(),
            None => {
                println!("Error Couldn't find content-type in request handler");
                return None;
            }
        };
        if content_type != "application/json" {
            println!("Error received content of type for which there is no handler");
            return None;
        }

        let content_str: &String = header.last().unwrap();
        let reid_json: ReidMessage = serde_json::from_str(content_str).unwrap();
        let reid_b64: String = reid_json.reid;
        let reid_raw: String = String::from_utf8(decode_block(&reid_b64).unwrap()).unwrap();
        match serde_json::from_str(&reid_raw) {
            Err(why) => {
                println!("Error deserializing reid json string: {why}");
                None
            }
            Ok(reid) => reid,
        }
    }
*/
    pub fn append_anchor(&mut self, anchor_type: AnchorType, anchor_value: String) {
        self.anchors
            .get_or_insert_with(Vec::new)
            .push((anchor_type, anchor_value));
    }

    pub fn append_claim(&mut self, claim_type: ClaimType, claim_value: Key) {
        self.claims
            .get_or_insert_with(Vec::new)
            .push((claim_type, claim_value));
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    pub fn key_to_pem(key: &Key) -> String {
        let key_value: &String = &key.1;
        if key.0 == KeyType::ED25519 {
            key_value.clone()
        } else if key.0 == KeyType::CHACHA20POLY1305 {
            key_value.clone()
        } else {
            println!("Displaying unsupported key type, using base64");
            encode_block(key_value.as_bytes())
        }
    }

    pub fn get_id(&self) -> Id {
        self.id.clone()
    }

    pub fn update_sig(&mut self, prv_key: &PKey<Private>) -> std::result::Result<Sig, ErrorStack> {
        Reid::sign_reid(prv_key, self)
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    fn sign_reid(
        prv_key: &PKey<Private>,
        reid: &Reid,
    ) -> std::result::Result<Sig, openssl::error::ErrorStack> {
        let mut signer = Signer::new_without_digest(prv_key).unwrap();
        let reid_data: Vec<u8> = Reid::reid_to_signable(reid); // Char vector that will be signed
        let mut sig = vec![0u8; reid_data.len()];
        if let Err(why) = signer.sign_oneshot(&mut sig, &reid_data) {
            panic!("Signer failed {why}")
        };
        Ok(sig.to_vec())
    }

    fn sign_reid_with_args(
        prv_key: &PKey<Private>,
        id: &Id,
        expiration: DateTime<Utc>,
        claims: &Option<Vec<(ClaimType, Key)>>,
        anchors: &Option<Vec<(AnchorType, String)>>,
    ) -> std::result::Result<Sig, openssl::error::ErrorStack> {
        let mut signer = Signer::new_without_digest(prv_key).unwrap();
        let reid_data: Vec<u8> = Reid::args_to_signable(id, expiration, claims, anchors); // Char vector that will be signed
        let mut sig = vec![0u8; Signer::len(&signer).unwrap()];
        if let Err(why) = signer.sign_oneshot(&mut sig, &reid_data) {
            panic!("Signer failed {why}")
        };
        Ok(sig.to_vec())
    }

    pub fn verify_sig(&self, pub_key: &PKey<Public>) -> bool {
        let mut verify = Verifier::new_without_digest(pub_key).unwrap();
        let data: Vec<u8> = Reid::reid_to_signable(self);
        verify.verify_oneshot(&self.sig, &data).unwrap()
    }

    fn reid_to_signable(reid: &Reid) -> Vec<u8> {
        Reid::args_to_signable(&reid.id, reid.expiration, &reid.claims, &reid.anchors)
    }

    fn args_to_signable(
        id: &Id,
        expiration: DateTime<Utc>,
        claims: &Option<Vec<(ClaimType, Key)>>,
        anchors: &Option<Vec<(AnchorType, String)>>,
    ) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        data.extend(id.clone().iter());

        let claims_clone: Option<Vec<(ClaimType, Key)>> = claims.clone();
        if let Some(claim_val) = claims_clone {
            let claim_raw: Vec<u8> = claim_val
                .into_iter()
                .flat_map(|(ct, k)| {
                    let mut combined: Vec<u8> = vec![ct as u8];
                    combined.push(k.0 as u8);
                    combined.extend(k.1.clone().into_bytes());
                    combined
                })
                .collect();
            data.extend(claim_raw);
        }

        let anchors_clone: Option<Vec<(AnchorType, String)>> = anchors.clone();
        if let Some(anchor_val) = anchors_clone {
            let anchor_raw: Vec<u8> = anchor_val
                .into_iter()
                .flat_map(|(at, av)| {
                    let mut combined: Vec<u8> = vec![at as u8];
                    combined.extend(av.into_bytes());
                    combined
                })
                .collect();
            data.extend(anchor_raw);
        }

        let exp_raw: Vec<u8> = expiration.clone().to_rfc3339().into_bytes();
        data.extend(exp_raw);
        data
    }
}

impl Encodable for Reid {
    fn encode(&self) -> String {
        encode_block(self.to_json().as_bytes())
    }
}

impl Decodable<Reid> for Reid {
    fn decode(reid_b64: &str) -> Option<Reid> {
        let reid_vec: Vec<u8> = match decode_block(reid_b64) {
            Err(why) => {
                println!("Error decoding reid base64: {why}");
                return None;
            }
            Ok(vec) => vec,
        };
        let reid_json: String = match String::from_utf8(reid_vec) {
            Err(why) => {
                // TODO should analyze deocode_block from openssl
                // because I think this should be impossible
                println!("Error parsing decoded base64 vector into string: {why}");
                return None;
            }
            Ok(str) => str,
        };
        match serde_json::from_str(&reid_json) {
            Err(why) => {
                println!("Error decoding reid_json into Reid object: {why}");
                None
            }
            Ok(reid) => reid,
        }
    }
}

impl fmt::Display for Reid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // id
        writeln!(f, "id: {}", encode_block(&self.id))?;

        // pow
        match &self.pow {
            Some(pow) => writeln!(f, "pow: {}", encode_block(pow))?,
            None => writeln!(f, "pow: None")?,
        }

        // expiration
        writeln!(f, "expiration: {}", self.expiration.to_rfc3339())?;

        // sig
        writeln!(f, "sig: {}", encode_block(&self.sig))?;

        // claims
        writeln!(f, "claims:")?;
        match &self.claims {
            Some(claims) => {
                for (name, key) in claims {
                    writeln!(f, "- {}: {}", name, Reid::key_to_pem(key))?;
                }
            }
            None => writeln!(f, "None")?,
        }

        // anchors
        writeln!(f, "anchors:")?;
        match &self.anchors {
            Some(anchors) => {
                for (name, value) in anchors {
                    writeln!(f, "- {}: {}", name, value)?;
                }
            }
            None => writeln!(f, "None")?,
        }

        // revoked
        writeln!(
            f,
            "revoked: {}",
            if self.revoked { "True" } else { "False" }
        )?;

        Ok(())
    }
}
