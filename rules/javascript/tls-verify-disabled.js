const https = require("https");

// ruleid: shipguard.javascript.tls-verify-disabled
const insecure = new https.Agent({ rejectUnauthorized: false });

// ruleid: shipguard.javascript.tls-verify-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// ok: shipguard.javascript.tls-verify-disabled
const secure = new https.Agent({ rejectUnauthorized: true });
