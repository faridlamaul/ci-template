export async function bad(db: any, name: string) {
  // ruleid: shipguard.javascript.sql-injection
  await db.query(`SELECT * FROM users WHERE name = '${name}'`);
}

export async function good(db: any, name: string) {
  // ok: shipguard.javascript.sql-injection
  await db.query("SELECT * FROM users WHERE name = $1", [name]);
}
