package main

import (
	"context"
	"database/sql"
	"fmt"
)

func bad(db *sql.DB, ctx context.Context, name string) {
	// ruleid: shipguard.go.sql-injection
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
	// ruleid: shipguard.go.sql-injection
	db.Exec("DELETE FROM users WHERE name = '" + name + "'")
	// ruleid: shipguard.go.sql-injection
	db.QueryRowContext(ctx, "SELECT id FROM users WHERE name = '"+name+"'")
}

func badTwoStep(db *sql.DB, name string) {
	q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	// ruleid: shipguard.go.sql-injection
	db.Query(q)
	stmt := "SELECT * FROM users WHERE name = '" + name + "'"
	// ruleid: shipguard.go.sql-injection
	db.Exec(stmt)
}

func good(db *sql.DB, ctx context.Context, name string) {
	// ok: shipguard.go.sql-injection
	db.Query("SELECT * FROM users WHERE name = $1", name)
	// ok: shipguard.go.sql-injection
	db.ExecContext(ctx, "DELETE FROM users "+"WHERE name = $1", name)
	msg := fmt.Sprintf("looking up %s", name)
	fmt.Println(msg)
	// ok: shipguard.go.sql-injection
	db.Query("SELECT 1 WHERE $1 = $1", msg)
}
