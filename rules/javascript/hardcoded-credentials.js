function bad() {
  // ruleid: shipguard.javascript.hardcoded-credentials
  const dbPassword = "changeme-not-a-secret";
  // ruleid: shipguard.javascript.hardcoded-credentials
  const cfg = { apiKey: "changeme-not-a-secret" };
  return [dbPassword, cfg];
}

function good() {
  // ok: shipguard.javascript.hardcoded-credentials
  const dbPassword = process.env.DB_PASSWORD;
  // ok: shipguard.javascript.hardcoded-credentials
  const tokenHeader = "";
  return [dbPassword, tokenHeader];
}
