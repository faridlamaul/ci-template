use std::process::Command;

fn bad(user: &str) {
    // ruleid: shipguard.rust.command-injection
    Command::new("sh").arg("-c").arg(format!("ls {}", user)).output().unwrap();
    // ruleid: shipguard.rust.command-injection
    Command::new("bash").args(["-c", user]).output().unwrap();
}

fn good(user: &str) {
    // ok: shipguard.rust.command-injection
    Command::new("ls").arg(user).output().unwrap();
    // ok: shipguard.rust.command-injection
    Command::new("sh").arg("-c").arg("echo hello").output().unwrap();
}
