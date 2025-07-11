use chrono::{DateTime, Utc};

type Id = Vec<u8>;
type Key = Vec<u8>;
type Sig = Vec<u8>;

struct Reid {
    id: Id, 
    pow: Vec<u8>,
    expiration: DateTime<Utc>,
    sig: Sig,
    claims: Vec<Key>,
    anchors: Vec<String>,
    revoked: bool,
}

struct Endorsement {
    endorsing_id: Id,
    expiration: DateTime<Utc>,
    sig: Sig,
    pow: Vec<u8>,
    endorsements: Vec<(Id, (Key, String))>,
}
