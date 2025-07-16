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
