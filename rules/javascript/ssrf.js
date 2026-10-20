const axios = require("axios");

async function bad(req) {
  // ruleid: shipguard.javascript.ssrf
  await fetch(req.query.url);
  const target = req.body.callback;
  // ruleid: shipguard.javascript.ssrf
  await axios.get(target);
}

async function good() {
  // ok: shipguard.javascript.ssrf
  await fetch("https://api.example.com/health");
}

async function goodBody(req) {
  // ok: shipguard.javascript.ssrf
  await fetch("https://api.example.com/x", { method: "POST", body: JSON.stringify(req.body.x) });
  // ok: shipguard.javascript.ssrf
  await axios.post("https://api.example.com/x", { q: req.body.q });
}
