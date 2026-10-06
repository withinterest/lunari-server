import assert from "node:assert/strict";
import test from "node:test";

import { createVerifyHandler } from "../api/google-play/verify.js";

const validCredentials = JSON.stringify({
  client_email: "billing@example.invalid",
  private_key: "test-private-key",
  private_key_id: "test-key-id",
});

function request({ method = "POST", body } = {}) {
  return { method, body };
}

function responseRecorder() {
  return {
    statusCode: 200,
    body: null,
    headers: {},
    status(value) {
      this.statusCode = value;
      return this;
    },
    json(value) {
      this.body = value;
      return this;
    },
    setHeader(name, value) {
      this.headers[name] = value;
    },
  };
}

function validBody(overrides = {}) {
  return {
    packageName: "com.lunari.app",
    productId: "lunari_stars_30",
    purchaseToken: "test-purchase-token",
    claimantId: "installation-12345678",
    ...overrides,
  };
}

function successfulClaim(overrides = {}) {
  return {
    claimId: "11111111-1111-4111-8111-111111111111",
    sameClaimant: true,
    idempotentReplay: false,
    ...overrides,
  };
}

function handlerWith(verifyPurchase, env = {}, claimPurchase = async () => successfulClaim()) {
  return createVerifyHandler({
    verifyPurchase,
    claimPurchase,
    env: {
      GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: validCredentials,
      DATABASE_URL: "postgresql://example.invalid/database",
      PURCHASE_TOKEN_HMAC_SECRET: "test-secret-with-at-least-32-characters",
      ...env,
    },
    logger: { error() {} },
  });
}

async function invoke(handler, req) {
  const res = responseRecorder();
  await handler(req, res);
  return res;
}

test("GET returns 405", async () => {
  const res = await invoke(handlerWith(async () => ({})), request({ method: "GET" }));
  assert.equal(res.statusCode, 405);
  assert.equal(res.body.code, "METHOD_NOT_ALLOWED");
  assert.equal(res.headers.Allow, "POST");
});

test("missing body returns 400", async () => {
  const res = await invoke(handlerWith(async () => ({})), request());
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.code, "INVALID_REQUEST");
});

test("wrong package is rejected before verification", async () => {
  const res = await invoke(
    handlerWith(async () => assert.fail("must not call Google")),
    request({ body: validBody({ packageName: "com.example.other" }) }),
  );
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, "PACKAGE_NOT_ALLOWED");
});

test("wrong product is rejected before verification", async () => {
  const res = await invoke(
    handlerWith(async () => assert.fail("must not call Google")),
    request({ body: validBody({ productId: "other_product" }) }),
  );
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, "PRODUCT_NOT_ALLOWED");
});

test("missing token is rejected", async () => {
  const res = await invoke(
    handlerWith(async () => assert.fail("must not call Google")),
    request({ body: validBody({ purchaseToken: "" }) }),
  );
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.code, "MISSING_PURCHASE_TOKEN");
});

test("missing service account environment variable is safe", async () => {
  const handler = createVerifyHandler({
    verifyPurchase: async () => assert.fail("must not call Google"),
    env: {},
    logger: { error() {} },
  });
  const res = await invoke(handler, request({ body: validBody() }));
  assert.equal(res.statusCode, 500);
  assert.deepEqual(res.body, {
    ok: false,
    verified: false,
    grantApproved: false,
    code: "SERVER_CONFIG_ERROR",
  });
});

test("malformed service account JSON is safe", async () => {
  const res = await invoke(
    handlerWith(async () => assert.fail("must not call Google"), {
      GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: "{broken",
    }),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 500);
  assert.equal(res.body.code, "SERVER_CONFIG_ERROR");
});

test("missing credential fields are rejected", async () => {
  const res = await invoke(
    handlerWith(async () => assert.fail("must not call Google"), {
      GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: JSON.stringify({
        client_email: "billing@example.invalid",
      }),
    }),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 500);
  assert.equal(res.body.code, "SERVER_CONFIG_ERROR");
});

test("purchased target product is verified with server grant policy", async () => {
  const res = await invoke(
    handlerWith(async () => ({
      purchaseStateContext: { purchaseState: "PURCHASED" },
      productLineItem: [
        {
          productId: "lunari_stars_30",
          productOfferDetails: { refundableQuantity: 1 },
        },
      ],
    })),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body, {
    ok: true,
    verified: true,
    grantApproved: true,
    claimed: true,
    idempotentReplay: false,
    claimId: "11111111-1111-4111-8111-111111111111",
    productId: "lunari_stars_30",
    grantStars: 30,
    status: "purchased",
  });
});

test("missing and invalid claimant ids are rejected before verification", async () => {
  for (const [claimantId, expectedCode] of [
    ["", "MISSING_CLAIMANT_ID"],
    ["short", "INVALID_CLAIMANT_ID"],
    ["invalid claimant value!", "INVALID_CLAIMANT_ID"],
  ]) {
    const res = await invoke(
      handlerWith(async () => assert.fail("must not call Google")),
      request({ body: validBody({ claimantId }) }),
    );
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.code, expectedCode);
  }
});

test("missing database URL returns a safe configuration error", async () => {
  const res = await invoke(
    handlerWith(async () => assert.fail("must not call Google"), {
      DATABASE_URL: "",
    }),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 500);
  assert.equal(res.body.code, "DB_CONFIG_ERROR");
  assert.equal(res.body.grantApproved, false);
});

test("missing HMAC secret returns a safe configuration error", async () => {
  const res = await invoke(
    handlerWith(async () => assert.fail("must not call Google"), {
      PURCHASE_TOKEN_HMAC_SECRET: "",
    }),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 500);
  assert.equal(res.body.code, "SERVER_CONFIG_ERROR");
  assert.equal(res.body.grantApproved, false);
});

test("claim receives an HMAC identifier and server grant policy", async () => {
  let captured;
  const token = "raw-token-must-not-be-stored";
  const res = await invoke(
    handlerWith(
      async () => ({
        purchaseStateContext: { purchaseState: "PURCHASED" },
        productLineItem: [{ productId: "lunari_stars_30" }],
        orderId: "order-id",
      }),
      {},
      async (claim) => {
        captured = claim;
        return successfulClaim();
      },
    ),
    request({ body: validBody({ purchaseToken: token, grantStars: 999 }) }),
  );

  assert.equal(res.statusCode, 200);
  assert.equal(captured.grantStars, 30);
  assert.equal(captured.googleOrderId, "order-id");
  assert.match(captured.tokenHash, /^[0-9a-f]{64}$/);
  assert.notEqual(captured.tokenHash, token);
  assert.equal(JSON.stringify(captured).includes(token), false);
});

test("same claimant replay returns the stable claim id", async () => {
  const claimId = "22222222-2222-4222-8222-222222222222";
  const res = await invoke(
    handlerWith(
      async () => ({
        purchaseStateContext: { purchaseState: "PURCHASED" },
        productLineItem: [{ productId: "lunari_stars_30" }],
      }),
      {},
      async () => successfulClaim({ claimId, idempotentReplay: true }),
    ),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.claimId, claimId);
  assert.equal(res.body.idempotentReplay, true);
  assert.equal(res.body.grantApproved, true);
});

test("a different claimant cannot reuse an existing token", async () => {
  const res = await invoke(
    handlerWith(
      async () => ({
        purchaseStateContext: { purchaseState: "PURCHASED" },
        productLineItem: [{ productId: "lunari_stars_30" }],
      }),
      {},
      async () => successfulClaim({
        sameClaimant: false,
        idempotentReplay: true,
      }),
    ),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 409);
  assert.deepEqual(res.body, {
    ok: false,
    verified: true,
    grantApproved: false,
    code: "ALREADY_CLAIMED",
  });
});

test("concurrent same-token claims produce one first claim and one replay", async () => {
  const claimId = "33333333-3333-4333-8333-333333333333";
  let storedClaim = null;
  const claimPurchase = async ({ tokenHash, claimantId }) => {
    if (storedClaim == null) {
      storedClaim = { tokenHash, claimantId, claimId };
      return successfulClaim({ claimId, idempotentReplay: false });
    }
    return successfulClaim({
      claimId: storedClaim.claimId,
      sameClaimant: storedClaim.claimantId === claimantId,
      idempotentReplay: true,
    });
  };
  const handler = handlerWith(
    async () => ({
      purchaseStateContext: { purchaseState: "PURCHASED" },
      productLineItem: [{ productId: "lunari_stars_30" }],
    }),
    {},
    claimPurchase,
  );

  const [first, second] = await Promise.all([
    invoke(handler, request({ body: validBody() })),
    invoke(handler, request({ body: validBody() })),
  ]);

  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 200);
  assert.deepEqual(
    [first.body.idempotentReplay, second.body.idempotentReplay].sort(),
    [false, true],
  );
  assert.equal(first.body.claimId, second.body.claimId);
});

test("Google verification failures never attempt a database claim", async () => {
  let claimAttempts = 0;
  const res = await invoke(
    handlerWith(
      async () => ({
        purchaseStateContext: { purchaseState: "PENDING" },
        productLineItem: [{ productId: "lunari_stars_30" }],
      }),
      {},
      async () => {
        claimAttempts++;
        return successfulClaim();
      },
    ),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.code, "PURCHASE_PENDING");
  assert.equal(claimAttempts, 0);
});

test("refunded purchases never attempt a database claim", async () => {
  let claimAttempts = 0;
  const res = await invoke(
    handlerWith(
      async () => ({
        purchaseStateContext: { purchaseState: "PURCHASED" },
        productLineItem: [{
          productId: "lunari_stars_30",
          productOfferDetails: { refundableQuantity: 0 },
        }],
      }),
      {},
      async () => {
        claimAttempts++;
        return successfulClaim();
      },
    ),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 422);
  assert.equal(res.body.code, "PURCHASE_REFUNDED");
  assert.equal(claimAttempts, 0);
});

test("database failures never approve a grant", async () => {
  const { ClaimStorageError } = await import("../lib/purchase-claim-store.js");
  const logs = [];
  const handler = createVerifyHandler({
    verifyPurchase: async () => ({
      purchaseStateContext: { purchaseState: "PURCHASED" },
      productLineItem: [{ productId: "lunari_stars_30" }],
    }),
    claimPurchase: async () => { throw new ClaimStorageError(); },
    env: {
      GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: validCredentials,
      DATABASE_URL: "postgresql://secret.invalid/database",
      PURCHASE_TOKEN_HMAC_SECRET: "test-secret-with-at-least-32-characters",
    },
    logger: { error(value) { logs.push(value); } },
  });
  const res = await invoke(handler, request({ body: validBody() }));
  assert.equal(res.statusCode, 503);
  assert.deepEqual(res.body, {
    ok: false,
    verified: true,
    grantApproved: false,
    code: "CLAIM_STORAGE_UNAVAILABLE",
  });
  assert.equal(JSON.stringify(logs).includes("postgresql://"), false);
});

test("pending purchase is not approved", async () => {
  const res = await invoke(
    handlerWith(async () => ({
      purchaseStateContext: { purchaseState: "PENDING" },
      productLineItem: [{ productId: "lunari_stars_30" }],
    })),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.verified, false);
  assert.equal(res.body.code, "PURCHASE_PENDING");
});

test("canceled and unknown states are not approved", async () => {
  for (const purchaseState of ["CANCELLED", "PURCHASE_STATE_UNSPECIFIED"]) {
    const res = await invoke(
      handlerWith(async () => ({
        purchaseStateContext: { purchaseState },
        productLineItem: [{ productId: "lunari_stars_30" }],
      })),
      request({ body: validBody() }),
    );
    assert.equal(res.statusCode, 422);
    assert.equal(res.body.code, "PURCHASE_NOT_VERIFIED");
  }
});

test("fully refunded line item is not approved", async () => {
  const res = await invoke(
    handlerWith(async () => ({
      purchaseStateContext: { purchaseState: "PURCHASED" },
      productLineItem: [
        {
          productId: "lunari_stars_30",
          productOfferDetails: { refundableQuantity: 0 },
        },
      ],
    })),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 422);
  assert.equal(res.body.code, "PURCHASE_REFUNDED");
});

test("a response without the allowed product is rejected", async () => {
  const res = await invoke(
    handlerWith(async () => ({
      purchaseStateContext: { purchaseState: "PURCHASED" },
      productLineItem: [{ productId: "different_product" }],
    })),
    request({ body: validBody() }),
  );
  assert.equal(res.statusCode, 422);
  assert.equal(res.body.code, "PRODUCT_MISMATCH");
});

test("Google not-found response is sanitized", async () => {
  const token = "sensitive-token-that-must-not-leak";
  const credential = "sensitive-private-key-that-must-not-leak";
  const logs = [];
  const handler = createVerifyHandler({
    env: {
      GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: validCredentials,
      DATABASE_URL: "postgresql://example.invalid/database",
      PURCHASE_TOKEN_HMAC_SECRET: "test-secret-with-at-least-32-characters",
    },
    logger: { error(value) { logs.push(value); } },
    verifyPurchase: async () => {
      const error = new Error(`not found ${token} ${credential}`);
      error.response = { status: 404, data: { token, credential } };
      throw error;
    },
  });
  const res = await invoke(handler, request({ body: validBody({ purchaseToken: token }) }));
  assert.equal(res.statusCode, 404);
  assert.equal(res.body.code, "PURCHASE_NOT_FOUND");
  const exposed = JSON.stringify({ body: res.body, logs });
  assert.equal(exposed.includes(token), false);
  assert.equal(exposed.includes(credential), false);
});

test("Google permission and transient errors use safe codes", async () => {
  for (const [googleStatus, expectedStatus, expectedCode] of [
    [403, 502, "GOOGLE_API_PERMISSION_ERROR"],
    [429, 503, "GOOGLE_API_UNAVAILABLE"],
    [500, 503, "GOOGLE_API_UNAVAILABLE"],
  ]) {
    const res = await invoke(
      handlerWith(async () => {
        const error = new Error("unsafe upstream detail");
        error.response = { status: googleStatus };
        throw error;
      }),
      request({ body: validBody() }),
    );
    assert.equal(res.statusCode, expectedStatus);
    assert.equal(res.body.code, expectedCode);
  }
});

