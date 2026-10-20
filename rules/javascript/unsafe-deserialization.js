const serialize = require("node-serialize");
const yaml = require("js-yaml");

function bad(payload, text) {
  // ruleid: shipguard.javascript.unsafe-deserialization
  serialize.unserialize(payload);
  // ruleid: shipguard.javascript.unsafe-deserialization
  yaml.load(text, { schema: yaml.DEFAULT_FULL_SCHEMA });
}

function good(payload, text) {
  // ok: shipguard.javascript.unsafe-deserialization
  JSON.parse(payload);
  // ok: shipguard.javascript.unsafe-deserialization
  yaml.load(text);
}
