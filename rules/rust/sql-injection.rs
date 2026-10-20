async fn bad(pool: &sqlx::PgPool, name: &str) {
    // ruleid: shipguard.rust.sql-injection
    sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", name))
        .fetch_all(pool)
        .await
        .unwrap();
    // ruleid: shipguard.rust.sql-injection
    let _q = diesel::sql_query(format!("DELETE FROM users WHERE name = '{}'", name));
}

fn bad_other(conn: &rusqlite::Connection, name: &str) {
    // ruleid: shipguard.rust.sql-injection
    conn.execute(&format!("DELETE FROM t WHERE n = '{}'", name), []).unwrap();
}

async fn bad_two_step(pool: &sqlx::PgPool, name: &str) {
    let sql = format!("SELECT * FROM users WHERE name = '{}'", name);
    // ruleid: shipguard.rust.sql-injection
    sqlx::query(&sql).fetch_all(pool).await.unwrap();
}

async fn good(pool: &sqlx::PgPool, name: &str) {
    // ok: shipguard.rust.sql-injection
    sqlx::query("SELECT * FROM users WHERE name = $1")
        .bind(name)
        .fetch_all(pool)
        .await
        .unwrap();
}

fn good_log(name: &str) {
    let msg = format!("looking up {}", name);
    println!("{}", msg);
}
