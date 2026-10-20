function bad(db, name) {
  // ruleid: shipguard.javascript.sql-injection
  db.query("SELECT * FROM users WHERE name = '" + name + "'");
  // ruleid: shipguard.javascript.sql-injection
  db.query(`SELECT * FROM users WHERE name = '${name}'`);
  // ruleid: shipguard.javascript.sql-injection
  db.$queryRawUnsafe("SELECT * FROM users WHERE name = '" + name + "'");
}

function badTwoStep(db, name) {
  const q = "SELECT * FROM users WHERE name = '" + name + "'";
  // ruleid: shipguard.javascript.sql-injection
  db.query(q);
}

async function good(db, prisma, name, id) {
  // ok: shipguard.javascript.sql-injection
  db.query("SELECT * FROM users WHERE name = $1", [name]);
  // ok: shipguard.javascript.sql-injection
  db.query("SELECT * FROM users " + "WHERE name = $1", [name]);
  // ok: shipguard.javascript.sql-injection
  await prisma.$queryRawUnsafe("SELECT * FROM users WHERE id = $1", id);
}
