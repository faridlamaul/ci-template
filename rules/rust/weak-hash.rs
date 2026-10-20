fn bad(data: &[u8]) {
    // ruleid: shipguard.rust.weak-hash
    let _a = md5::compute(data);
    // ruleid: shipguard.rust.weak-hash
    let _b = Sha1::new();
}

fn good(data: &[u8]) {
    // ok: shipguard.rust.weak-hash
    let _c = Sha256::digest(data);
}
