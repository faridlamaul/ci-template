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

fn good_reqwest(client: &reqwest::blocking::Client, id: u32) {
    // ok: shipguard.rust.sql-injection
    let req = client.get(format!("https://api.example.com/{}", id)).build().unwrap();
    // ok: shipguard.rust.sql-injection
    client.execute(req).unwrap();
    // ok: shipguard.rust.sql-injection
    client.get("https://api.example.com").query(&[("q", format!("{}", id))]);
}

fn bad_postgres(client: &mut postgres::Client, name: &str) {
    // ruleid: shipguard.rust.sql-injection
    client.simple_query(&format!("SELECT * FROM t WHERE n = '{}'", name)).unwrap();
    // ruleid: shipguard.rust.sql-injection
    client.batch_execute(&format!("DROP TABLE {}", name)).unwrap();
    // ruleid: shipguard.rust.sql-injection
    client.execute(&format!("DELETE FROM t WHERE n = '{}'", name), &[]).unwrap();
    // ruleid: shipguard.rust.sql-injection
    client.query(format!("SELECT * FROM t WHERE n = '{}'", name).as_str(), &[]).unwrap();
    // ruleid: shipguard.rust.sql-injection
    client.query_one(format!("SELECT * FROM t WHERE n = '{}'", name).as_str(), &[]).unwrap();
    // ruleid: shipguard.rust.sql-injection
    client.query_opt(&format!("SELECT * FROM t WHERE n = '{}'", name), &[]).unwrap();
}

fn bad_rusqlite(conn: &rusqlite::Connection, name: &str) {
    // ruleid: shipguard.rust.sql-injection
    conn.execute_batch(&format!("DELETE FROM t WHERE n = '{}'", name)).unwrap();
    let sql = format!("SELECT id FROM t WHERE n = '{}'", name);
    // ruleid: shipguard.rust.sql-injection
    let _id: i64 = conn.query_row(&sql, [], |r| r.get(0)).unwrap();
    // ruleid: shipguard.rust.sql-injection
    let _s = conn.prepare_cached(&sql).unwrap();
}

fn bad_diesel(conn: &mut diesel::PgConnection, name: &str) {
    // ruleid: shipguard.rust.sql-injection
    diesel::sql_query(format!("SELECT * FROM t WHERE n = '{}'", name)).execute(conn).unwrap();
}

async fn bad_sqlx_raw(pool: &sqlx::PgPool, name: &str) {
    // ruleid: shipguard.rust.sql-injection
    sqlx::raw_sql(&format!("DELETE FROM t WHERE n = '{}'", name)).execute(pool).await.unwrap();
}

fn good_parameterized(client: &mut postgres::Client, conn: &rusqlite::Connection, name: &str) {
    // ok: shipguard.rust.sql-injection
    client.query("SELECT * FROM t WHERE n = $1", &[&name]).unwrap();
    // ok: shipguard.rust.sql-injection
    client.execute("DELETE FROM t WHERE n = $1", &[&format!("{}%", name)]).unwrap();
    // ok: shipguard.rust.sql-injection
    let _id: i64 = conn.query_row("SELECT id FROM t WHERE n = ?1", [format!("{}%", name)], |r| r.get(0)).unwrap();
    // ok: shipguard.rust.sql-injection
    client.simple_query("SELECT 1").unwrap();
    // ok: shipguard.rust.sql-injection
    conn.execute_batch("CREATE TABLE t (n TEXT)").unwrap();
}
