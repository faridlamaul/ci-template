fn bad() {
    // ruleid: shipguard.rust.tls-verify-disabled
    let _c = reqwest::Client::builder().danger_accept_invalid_certs(true).build();
}

fn good() {
    // ok: shipguard.rust.tls-verify-disabled
    let _c = reqwest::Client::builder().danger_accept_invalid_certs(false).build();
    // ok: shipguard.rust.tls-verify-disabled
    let _d = reqwest::Client::builder().build();
}
