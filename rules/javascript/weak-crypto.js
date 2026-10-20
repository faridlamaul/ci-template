const crypto = require("crypto");

function bad(data) {
  // ruleid: shipguard.javascript.weak-crypto
  crypto.createHash("md5").update(data).digest("hex");
  // ruleid: shipguard.javascript.weak-crypto
  crypto.createHash("sha1").update(data);
}

function good(data) {
  // ok: shipguard.javascript.weak-crypto
  crypto.createHash("sha256").update(data).digest("hex");
}
