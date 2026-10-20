use std::process::Command;

fn bad(user: &str) {
    // ruleid: shipguard.rust.command-injection
    Command::new("sh").arg("-c").arg(format!("ls {}", user)).output().unwrap();
    // ruleid: shipguard.rust.command-injection
    Command::new("bash").args(["-c", user]).output().unwrap();
    // ruleid: shipguard.rust.command-injection
    Command::new("sh").args(&["-c", user]).output().unwrap();
}

fn bad_builder(user: &str) {
    let mut c = Command::new("sh");
    // ruleid: shipguard.rust.command-injection
    c.arg("-c").arg(user);
}

fn good(user: &str) {
    // ok: shipguard.rust.command-injection
    Command::new("ls").arg(user).output().unwrap();
    // ok: shipguard.rust.command-injection
    Command::new("sh").arg("-c").arg("echo hello").output().unwrap();
}

fn good_builder() {
    let mut c = Command::new("sh");
    // ok: shipguard.rust.command-injection
    c.arg("-c").arg("echo hello");
}
