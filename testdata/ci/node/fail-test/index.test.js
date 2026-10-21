'use strict';

// A bare top-level test, outside describe(), must count as a failure too.
const test = require('node:test');
const assert = require('node:assert');
const { add } = require('./index.js');

test('adds two numbers', () => {
  assert.strictEqual(add(2, 2), 5);
});
