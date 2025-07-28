use super::common::{Id, Key, Sig};
use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Endorsement {
    endorsing_id: Id,
    #[serde(with = "ts_seconds")]
    expiration: DateTime<Utc>,
    sig: Option<Sig>,
    pow: Option<Vec<u8>>,
    endorsements: Option<Vec<(Id, (String, Key))>>,
}

impl Endorsement {
    pub fn new(
        endorsing_id: Id,
        expiration: DateTime<Utc>,
        sig: Option<Sig>,
        pow: Option<Vec<u8>>,
        endorsements: Option<Vec<(Id, (String, Key))>>,
    ) -> Self {
        Self {
            endorsing_id,
            expiration,
            sig,
            pow,
            endorsements,
        }
    }

    fn args_to_signable () {
        // TODO Implement: move the logic for converting the
        // data into a signable format into this funciton then
        // create a sign and verify funciton that calls this funciton
        // similar to the patterin reid.rs
    }

    pub fn verify_sig() {
    }

    fn sign_endorsement(
        prv_key: PKey<Private>,
        endorsing_id: &Id,
        expiration: DateTime<Utc>,
        endorsements: &Option<Vec<(Id, (String, Key))>>,
    ) -> std::result::Result<Sig, openssl::error::ErrorStack> {
        let mut signer = Signer::new(MessageDigest::sha256(), &prv_key).unwrap();
        let mut end_data: Vec<u8> = Vec::new();

        end_data.extend(endorsing_id.clone().iter());

        let exp_raw: Vec<u8> = expiration.clone().to_rfc3339().into_bytes();
        end_data.extend(exp_raw);

        let endorsements_clone: Option<Vec<(Id, (String, Key))>> = endorsements.clone();
        if let Some(endorsement_vals) = endorsements_clone {
            let endorsement_raw: Vec<u8> = endorsement_vals
                .into_iter()
                .flat_map(|(i, (s, k))| {
                    let mut combined = Vec::new();
                    combined.extend(i);
                    combined.extend(s.clone().into_bytes());
                    combined.push(k.0 as u8); // Key type
                    combined.extend(k.1.clone().into_bytes()); // Key value
                    combined
                })
                .collect();
            end_data.extend(endorsement_raw);
        };

        if let Err(why) = signer.update(&end_data) {
            panic!("Signer failed somehow: {why}")
        };
        signer.sign_to_vec()
    }
}
