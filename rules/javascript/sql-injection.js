function bad(db, name) {
  // ruleid: shipguard.javascript.sql-injection
  db.query("SELECT * FROM users WHERE name = '" + name + "'");
  // ruleid: shipguard.javascript.sql-injection
  db.query(`SELECT * FROM users WHERE name = '${name}'`);
  // ruleid: shipguard.javascript.sql-injection
  db.$queryRawUnsafe("SELECT * FROM users WHERE name = '" + name + "'");
}

function good(db, name) {
  // ok: shipguard.javascript.sql-injection
  db.query("SELECT * FROM users WHERE name = $1", [name]);
  // ok: shipguard.javascript.sql-injection
  db.query("SELECT * FROM users " + "WHERE name = $1", [name]);
}
