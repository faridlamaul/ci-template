// ruleid: shipguard.rust.hardcoded-credentials
const DB_PASSWORD: &str = "changeme-not-a-secret";

fn bad() {
    // ruleid: shipguard.rust.hardcoded-credentials
    let api_token = "changeme-not-a-secret";
    let _ = api_token;
}

fn good() {
    // ok: shipguard.rust.hardcoded-credentials
    let db_password = std::env::var("DB_PASSWORD").unwrap_or_default();
    // ok: shipguard.rust.hardcoded-credentials
    let token_header = "";
    let _ = (db_password, token_header);
}
