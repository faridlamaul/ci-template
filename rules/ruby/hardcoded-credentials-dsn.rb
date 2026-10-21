def bad_dsn
  # ruleid: shipguard.ruby.hardcoded-credentials-dsn
  dsn = "postgres://app:s3cr3t-pw@db.internal:5432/app"
  # ruleid: shipguard.ruby.hardcoded-credentials-dsn
  connect(url: "mysql://root:hunter22@db:3306/app")
  # ruleid: shipguard.ruby.hardcoded-credentials-dsn
  connect("mongodb+srv://svc:Zx9-q7Lm@cluster0.example.net/app")
  # ruleid: shipguard.ruby.hardcoded-credentials-dsn
  connect("redis://:pass@cache:6379/0")
  dsn
end

def good_dsn
  # ok: shipguard.ruby.hardcoded-credentials-dsn
  connect("postgres://app:${DB_PASSWORD}@db:5432/app")
  # ok: shipguard.ruby.hardcoded-credentials-dsn
  connect("postgres://app:<password>@db:5432/app")
  # ok: shipguard.ruby.hardcoded-credentials-dsn
  connect("postgresql://user:password@localhost/app")
  # ok: shipguard.ruby.hardcoded-credentials-dsn
  connect("postgres://app@db:5432/app")
  # ok: shipguard.ruby.hardcoded-credentials-dsn
  connect(ENV["DATABASE_URL"])
  # ok: shipguard.ruby.hardcoded-credentials-dsn
  connect("postgres://app:#{ENV["DB_PASSWORD"]}@db/app")
end
