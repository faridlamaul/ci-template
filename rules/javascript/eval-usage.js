function bad(code) {
  // ruleid: shipguard.javascript.eval-usage
  eval(code);
  // ruleid: shipguard.javascript.eval-usage
  new Function("a", code);
}

function good() {
  // ok: shipguard.javascript.eval-usage
  eval("1 + 1");
  // ok: shipguard.javascript.eval-usage
  setTimeout(() => console.log("tick"), 10);
  // ok: shipguard.javascript.eval-usage
  JSON.parse("{}");
}
