const fs = require("fs");
const path = require("path");

function bad(req, res) {
  const name = req.query.file;
  // ruleid: shipguard.javascript.path-traversal
  fs.readFileSync(path.join("/srv/data", name));
  // ruleid: shipguard.javascript.path-traversal
  res.sendFile(req.params.name);
}

function good(req, res) {
  const name = path.basename(req.query.file);
  // ok: shipguard.javascript.path-traversal
  fs.readFileSync(path.join("/srv/data", name));
  // ok: shipguard.javascript.path-traversal
  fs.readFileSync("/etc/hostname");
}
