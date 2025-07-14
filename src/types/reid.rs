use super::common::{Id, Key, Sig};
use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use openssl::base64::encode_block;
use openssl::{
    error::ErrorStack,
    hash::{Hasher, MessageDigest},
    pkey::{PKey, Private, Public},
    sign::Signer,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Reid {
    id: Id,               // Hash of public key
    pow: Option<Vec<u8>>, // proof of work, optionally required by the log
    #[serde(with = "ts_seconds")]
    expiration: DateTime<Utc>, // datetime wherein which the record expires
    sig: Sig,             // signature
    claims: Option<Vec<(String, Key)>>,
    anchors: Option<Vec<(String, String)>>,
    revoked: bool,
}

impl Reid {
    pub fn new(
        id: Id,
        pow: Option<Vec<u8>>,
        expiration: DateTime<Utc>,
        sig: Sig,
        claims: Option<Vec<(String, Key)>>,
        anchors: Option<Vec<(String, String)>>,
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
        pub_key: PKey<Public>,
        prv_key: PKey<Private>,
        expiration: DateTime<Utc>,
        pow: Option<Vec<u8>>,
        claims: Option<Vec<(String, Key)>>,
        anchors: Option<Vec<(String, String)>>,
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

        let sig: Sig = match Reid::sign_reid(prv_key, &id, expiration, &claims, &anchors) {
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

    // pub fn new_from_decode;

    pub fn append_anchor(&mut self, anchor_type: String, anchor_value: String) {
        self.anchors
            .get_or_insert_with(Vec::new)
            .push((anchor_type, anchor_value));
    }

    pub fn append_claim(&mut self, key_type: String, key_value: Key) {
        self.claims
            .get_or_insert_with(Vec::new)
            .push((key_type, key_value));
    }

    pub fn encode(&mut self) -> String {
        encode_block(self.to_json().as_bytes())
    }

    pub fn to_json(&mut self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    pub fn update_sig(&mut self, prv_key: PKey<Private>) -> std::result::Result<Sig, ErrorStack> {
        Reid::sign_reid(
            prv_key,
            &self.id,
            self.expiration,
            &self.claims,
            &self.anchors,
        )
    }

    fn sign_reid(
        prv_key: PKey<Private>,
        id: &Id,
        expiration: DateTime<Utc>,
        claims: &Option<Vec<(String, Key)>>,
        anchors: &Option<Vec<(String, String)>>,
    ) -> std::result::Result<Sig, openssl::error::ErrorStack> {
        let mut signer = Signer::new_without_digest(&prv_key).unwrap();
        let mut reid_data: Vec<u8> = Vec::new(); // Char vector that will be signed

        reid_data.extend(id.clone().iter());

        let claims_clone: Option<Vec<(String, Key)>> = claims.clone();
        if let Some(claim_val) = claims_clone {
            let claim_raw: Vec<u8> = claim_val
                .into_iter()
                .flat_map(|(s, k)| {
                    let mut combined = s.into_bytes();
                    combined.extend(k);
                    combined
                })
                .collect();
            reid_data.extend(claim_raw);
        }

        let anchors_clone: Option<Vec<(String, String)>> = anchors.clone();
        if let Some(anchor_val) = anchors_clone {
            let anchor_raw: Vec<u8> = anchor_val
                .into_iter()
                .flat_map(|(s1, s2)| {
                    let mut combined = s1.into_bytes();
                    combined.extend(s2.into_bytes());
                    combined
                })
                .collect();
            reid_data.extend(anchor_raw);
        }

        let exp_raw: Vec<u8> = expiration.clone().to_rfc3339().into_bytes();
        reid_data.extend(exp_raw);

        let mut sig = vec![0u8; reid_data.len()];
        if let Err(why) = signer.sign_oneshot(&mut sig, &reid_data) {
            panic!("Signer failed {why}")
        };
        Ok(sig.to_vec())
    }
}
