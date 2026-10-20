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
  // ok: shipguard.javascript.hardcoded-credentials
  const tokenUrl = "https://auth.example.com/token";
  // ok: shipguard.javascript.hardcoded-credentials
  const passwordPrompt = "Enter your password now";
  // ok: shipguard.javascript.hardcoded-credentials
  const secretName = "db-credentials";
  // ok: shipguard.javascript.hardcoded-credentials
  const categorySecrets = "secrets";
  // ok: shipguard.javascript.hardcoded-credentials
  const secretKind = "token_type";
  return [dbPassword, tokenHeader, tokenUrl, passwordPrompt, secretName, categorySecrets, secretKind];
}
