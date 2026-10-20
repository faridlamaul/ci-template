const crypto = require("crypto");

function bad(data, key, iv) {
  // ruleid: shipguard.javascript.weak-crypto
  crypto.createHash("md5").update(data).digest("hex");
  // ruleid: shipguard.javascript.weak-crypto
  crypto.createHash("sha1").update(data);
  // ruleid: shipguard.javascript.weak-crypto
  crypto.createHash("MD5").update(data);
  // ruleid: shipguard.javascript.weak-crypto
  crypto.createCipheriv("des-ede3-cbc", key, iv);
  // ruleid: shipguard.javascript.weak-crypto
  crypto.createCipheriv("rc4", key, iv);
}

function good(data, key, iv) {
  // ok: shipguard.javascript.weak-crypto
  crypto.createHash("sha256").update(data).digest("hex");
  // ok: shipguard.javascript.weak-crypto
  crypto.createCipheriv("aes-256-gcm", key, iv);
}
