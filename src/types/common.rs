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
pub static AT_DNS: &str = "DNS";
pub static AT_EMAIL: &str = "EMAIL";
pub static AT_PHONE: &str = "PHONE";
pub static AT_IPADDR: &str = "IP-ADDR";

// CLMT => CLAIM_TYPE
pub static CLMT_SSHKEY: &str = "SSHKEY";
pub static CLMT_X509: &str = "X509";

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
