'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { add } = require('./index.js');

describe('add', () => {
  it('adds two numbers', () => {
    assert.strictEqual(add(2, 2), 4);
  });
});
