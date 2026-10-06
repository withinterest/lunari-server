import assert from "node:assert/strict";
import test from "node:test";

import fortuneHandler from "../api/fortune.js";
import iconHandler from "../api/icon.js";

function responseRecorder() {
  return {
    statusCode: 200,
    body: null,
    status(value) {
      this.statusCode = value;
      return this;
    },
    json(value) {
      this.body = value;
      return this;
    },
  };
}

test("existing fortune endpoint remains importable", () => {
  assert.equal(typeof fortuneHandler, "function");
});

test("existing icon endpoint still reads tracked JSON configuration", () => {
  const res = responseRecorder();
  iconHandler({ query: { element: "wood" } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.element, "wood");
  assert.match(res.body.imageUrl, /\/icons\/wood\//);
});
