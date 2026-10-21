package main

import "os"

func badDSN() {
	// ruleid: shipguard.go.hardcoded-credentials-dsn
	dsn := "postgres://app:s3cr3t-pw@db.internal:5432/app"
	// ruleid: shipguard.go.hardcoded-credentials-dsn
	open("mysql", "mysql://root:hunter22@tcp(db:3306)/app")
	// ruleid: shipguard.go.hardcoded-credentials-dsn
	open("mongo", "mongodb+srv://svc:Zx9-q7Lm@cluster0.example.net/app")
	// ruleid: shipguard.go.hardcoded-credentials-dsn
	open("redis", "redis://:pass@cache:6379/0")
	_ = dsn
}

func open(driver, dsn string) {}

func goodDSN() {
	// ok: shipguard.go.hardcoded-credentials-dsn
	open("postgres", "postgres://app:${DB_PASSWORD}@db:5432/app")
	// ok: shipguard.go.hardcoded-credentials-dsn
	open("postgres", "postgres://app:<password>@db:5432/app")
	// ok: shipguard.go.hardcoded-credentials-dsn
	open("postgres", "postgresql://user:password@localhost/app")
	// ok: shipguard.go.hardcoded-credentials-dsn
	open("postgres", "postgres://app@db:5432/app")
	// ok: shipguard.go.hardcoded-credentials-dsn
	open("postgres", os.Getenv("DATABASE_URL"))
	// ok: shipguard.go.hardcoded-credentials-dsn
	open("postgres", "postgres://app:"+os.Getenv("DB_PASSWORD")+"@db/app")
}
