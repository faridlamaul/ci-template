const child_process = require("child_process");

function bad(user) {
  // ruleid: shipguard.javascript.command-injection
  child_process.exec("ls " + user);
  // ruleid: shipguard.javascript.command-injection
  child_process.execSync(`cat ${user}`);
}

function good(user) {
  // ok: shipguard.javascript.command-injection
  child_process.execFile("ls", [user]);
  // ok: shipguard.javascript.command-injection
  child_process.exec("ls -l");
}
