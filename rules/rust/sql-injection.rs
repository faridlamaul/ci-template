async fn bad(pool: &sqlx::PgPool, name: &str) {
    // ruleid: shipguard.rust.sql-injection
    sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", name))
        .fetch_all(pool)
        .await
        .unwrap();
    // ruleid: shipguard.rust.sql-injection
    let _q = diesel::sql_query(format!("DELETE FROM users WHERE name = '{}'", name));
}

async fn good(pool: &sqlx::PgPool, name: &str) {
    // ok: shipguard.rust.sql-injection
    sqlx::query("SELECT * FROM users WHERE name = $1")
        .bind(name)
        .fetch_all(pool)
        .await
        .unwrap();
}
