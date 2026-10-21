fn connect(_url: &str) {}

fn bad_dsn() {
    // ruleid: shipguard.rust.hardcoded-credentials-dsn
    let dsn = "postgres://app:s3cr3t-pw@db.internal:5432/app";
    // ruleid: shipguard.rust.hardcoded-credentials-dsn
    connect("mysql://root:hunter22@db:3306/app");
    // ruleid: shipguard.rust.hardcoded-credentials-dsn
    connect("mongodb+srv://svc:Zx9-q7Lm@cluster0.example.net/app");
    // ruleid: shipguard.rust.hardcoded-credentials-dsn
    connect("redis://:pass@cache:6379/0");
    let _ = dsn;
}

fn good_dsn() {
    // ok: shipguard.rust.hardcoded-credentials-dsn
    connect("postgres://app:${DB_PASSWORD}@db:5432/app");
    // ok: shipguard.rust.hardcoded-credentials-dsn
    connect("postgres://app:<password>@db:5432/app");
    // ok: shipguard.rust.hardcoded-credentials-dsn
    connect("postgresql://user:password@localhost/app");
    // ok: shipguard.rust.hardcoded-credentials-dsn
    connect("postgres://app@db:5432/app");
    // ok: shipguard.rust.hardcoded-credentials-dsn
    connect(&std::env::var("DATABASE_URL").unwrap_or_default());
    // ok: shipguard.rust.hardcoded-credentials-dsn
    connect(&format!("postgres://app:{}@db/app", std::env::var("DB_PASSWORD").unwrap_or_default()));
}
