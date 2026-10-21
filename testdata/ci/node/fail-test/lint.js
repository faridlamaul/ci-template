'use strict';

// A tiny local check: a source file must not contain the word FIXME.
const fs = require('node:fs');

const files = ['index.js', 'index.test.js'];
let failed = false;
for (const f of files) {
  if (fs.readFileSync(f, 'utf8').includes('FIX' + 'ME')) {
    console.error(`${f}: remove the marker comment`);
    failed = true;
  }
}
process.exit(failed ? 1 : 0);
