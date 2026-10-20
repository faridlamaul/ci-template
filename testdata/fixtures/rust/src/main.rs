// Intentionally insecure shipguard test fixture.
fn main() {
    let _c = reqwest::Client::builder().danger_accept_invalid_certs(true).build();
}
