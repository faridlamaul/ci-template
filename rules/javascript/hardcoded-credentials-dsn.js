function badDsn(connect) {
  // ruleid: shipguard.javascript.hardcoded-credentials-dsn
  const dsn = "postgres://app:s3cr3t-pw@db.internal:5432/app";
  // ruleid: shipguard.javascript.hardcoded-credentials-dsn
  connect("mysql://root:hunter22@db:3306/app");
  // ruleid: shipguard.javascript.hardcoded-credentials-dsn
  connect({ url: "mongodb+srv://svc:Zx9-q7Lm@cluster0.example.net/app" });
  // ruleid: shipguard.javascript.hardcoded-credentials-dsn
  connect("redis://:pass@cache:6379/0");
  return dsn;
}

function goodDsn(connect) {
  // ok: shipguard.javascript.hardcoded-credentials-dsn
  connect("postgres://app:${DB_PASSWORD}@db:5432/app");
  // ok: shipguard.javascript.hardcoded-credentials-dsn
  connect("postgres://app:<password>@db:5432/app");
  // ok: shipguard.javascript.hardcoded-credentials-dsn
  connect("postgresql://user:password@localhost/app");
  // ok: shipguard.javascript.hardcoded-credentials-dsn
  connect("postgres://app@db:5432/app");
  // ok: shipguard.javascript.hardcoded-credentials-dsn
  connect(process.env.DATABASE_URL);
  // ok: shipguard.javascript.hardcoded-credentials-dsn
  connect(`postgres://app:${process.env.DB_PASSWORD}@db/app`);
}
