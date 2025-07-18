pub type Id = Vec<u8>;
pub type Key = Vec<u8>;
pub type Sig = Vec<u8>;

// AT => ANCHOR_TYPE
pub static AT_DNS: &str = "DNS";
pub static AT_EMAIL: &str = "EMAIL";
pub static AT_PHONE: &str = "PHONE";
pub static AT_IPADDR: &str = "IP-ADDR";

// CLMT => CLAIM_TYPE
pub static CLMT_SSHKEY: &str = "SSHKEY";
pub static CLMT_X509: &str = "X509";

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
