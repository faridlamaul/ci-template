fn bad(p: *const u8) -> u8 {
    // ruleid: shipguard.rust.unsafe-block
    unsafe { *p }
}

fn good(v: &[u8]) -> Option<u8> {
    // ok: shipguard.rust.unsafe-block
    v.first().copied()
}
