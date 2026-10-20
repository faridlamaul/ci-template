fn bad(key: &[u8]) {
    // ruleid: shipguard.rust.weak-cipher
    let _a = Des::new_from_slice(key);
    // ruleid: shipguard.rust.weak-cipher
    let _b = Rc4::new(key.into());
    // ruleid: shipguard.rust.weak-cipher
    let _t = TdesEde3::new_from_slice(key);
    // ruleid: shipguard.rust.weak-cipher
    let _c = Cipher::des_cbc();
}

fn good(key: &[u8]) {
    // ok: shipguard.rust.weak-cipher
    let _d = Aes256Gcm::new_from_slice(key);
}
