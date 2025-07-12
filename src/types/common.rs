pub type Id = Vec<u8>;
pub type Key = Vec<u8>;
pub type Sig = Vec<u8>;

// AT => ANCHOR_TYPE 
static AT_DNS: &str = "DNS";
static AT_EMAIL: &str = "EMAIL";
static AT_PHONE: &str = "PHONE";
static AT_ADDRESS: &str = "ADDRESS";

// CLMT => CLAIM_TYPE
static CLMT_SSHKEY: &str = "SSHKEY";
static CLMT_X509: &str = "X509";
