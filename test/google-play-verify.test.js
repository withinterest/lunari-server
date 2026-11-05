import assert from "node:assert/strict";
import test from "node:test";

import { createVerifyHandler } from "../api/google-play/verify.js";

const productionEnvironment = { VERCEL: "1", VERCEL_ENV: "production" };

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
      ...productionEnvironment,
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
    env: { ...productionEnvironment },
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
      ...productionEnvironment,
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
      ...productionEnvironment,
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


// Local Mock tests simulate Production explicitly; there is no NODE_ENV bypass.
for (const [name, environment] of [
  ['preview',{VERCEL:'1',VERCEL_ENV:'preview'}],
  ['development',{VERCEL:'1',VERCEL_ENV:'development'}],
  ['unknown',{VERCEL:'1',VERCEL_ENV:'staging'}],['missing-all',{}],
  ['missing-environment',{VERCEL:'1'}],['missing-vercel',{VERCEL_ENV:'production'}],
  ['false-vercel',{VERCEL:'0',VERCEL_ENV:'production'}],
  ['uppercase',{VERCEL:'1',VERCEL_ENV:'PRODUCTION'}],
  ['whitespace',{VERCEL:'1',VERCEL_ENV:'production '}],
  ['node-test-not-a-bypass',{NODE_ENV:'test'}],
]) test(`legacy gate rejects ${name} before request, credentials, Google and DB`,async()=>{
  let google=0,claims=0;
  const env=new Proxy(environment,{get(target,key){assert(['VERCEL','VERCEL_ENV'].includes(key),'No credential access');return target[key];}});
  const handler=createVerifyHandler({env,
    verifyPurchase:async()=>{google++;assert.fail('No Google call');},
    claimPurchase:async()=>{claims++;assert.fail('No DB call');},
    logger:{error(){assert.fail('No log');}}});
  const res=await invoke(handler,{get method(){assert.fail('No request processing');},get body(){assert.fail('No body parsing');}});
  assert.equal(res.statusCode,403);
  assert.deepEqual(res.body,{ok:false,verified:false,grantApproved:false,code:'LEGACY_PURCHASE_ENVIRONMENT_FORBIDDEN'});
  assert.equal(google,0);assert.equal(claims,0);
});

test('spoofed headers/body cannot turn Preview into Production',async()=>{
  const res=await invoke(createVerifyHandler({env:{VERCEL:'1',VERCEL_ENV:'preview'},
    verifyPurchase:async()=>assert.fail('No Google'),claimPurchase:async()=>assert.fail('No DB')}),
    {method:'POST',body:{...validBody(),VERCEL_ENV:'production'},headers:{'x-vercel-env':'production','x-forwarded-host':'production.invalid'}});
  assert.equal(res.statusCode,403);assert.equal(res.body.code,'LEGACY_PURCHASE_ENVIRONMENT_FORBIDDEN');
});

test('gate checks trusted environment on every request',async()=>{
  const env={...productionEnvironment,GOOGLE_PLAY_SERVICE_ACCOUNT_JSON:validCredentials,
    DATABASE_URL:'postgresql://fixture.invalid/db',PURCHASE_TOKEN_HMAC_SECRET:'PUBLIC_FIXTURE_SECRET_32_CHARACTERS_LONG'};
  let google=0,claims=0;
  const handler=createVerifyHandler({env,logger:{error(){}},verifyPurchase:async()=>{google++;return{purchaseStateContext:{purchaseState:'PURCHASED'},productLineItem:[{productId:'lunari_stars_30'}]};},claimPurchase:async()=>{claims++;return successfulClaim();}});
  assert.equal((await invoke(handler,request({body:validBody()}))).statusCode,200);
  env.VERCEL_ENV='preview';assert.equal((await invoke(handler,request({body:validBody()}))).statusCode,403);
  assert.equal(google,1);assert.equal(claims,1);
});

test('QA wallet GET keeps independent Preview gate',async()=>{
  const {createQaWalletHandler}=await import('../api/qa/wallet/me.js');
  const host='ep-silent-leaf-b3xp84bu.c-4.ap-southeast-1.aws.neon.tech',uid='public-fixture-account';
  const env={VERCEL:'1',VERCEL_ENV:'preview',VERCEL_URL:'qa.example.test',WALLET_ENV:'qa',FIREBASE_PROJECT_ID:'lunari-dev',
    WALLET_V2_QA_READ_ENABLED:'1',WALLET_V2_QA_READ_ALLOWED_UIDS:JSON.stringify([uid]),NEON_API_KEY:'PUBLIC_FIXTURE_KEY',
    WALLET_V2_QA_READ_ISSUER_DATABASE_URL:`postgresql://lunari_wallet_v2_issuer_sql_qa:PUBLIC_FIXTURE_PASSWORD@${host}/neondb?sslmode=verify-full&channel_binding=require`,
    WALLET_V2_QA_READ_EXECUTOR_DATABASE_URL:`postgresql://lunari_wallet_v2_exec_sql_qa:PUBLIC_FIXTURE_PASSWORD@${host}/neondb?sslmode=verify-full&channel_binding=require`};
  let reads=0;const handler=createQaWalletHandler({env,verifyToken:async()=>({uid}),readWallet:async u=>{reads++;assert.equal(u,uid);return{ok:true,userUid:uid,source:'qa-wallet-v2'};}});
  const res=responseRecorder();await handler({method:'GET',url:'/api/qa/wallet/me',query:{},headers:{host:'qa.example.test','x-forwarded-proto':'https','x-vercel-forwarded-for':'127.0.0.1',authorization:'Bearer PUBLIC_FIXTURE_TOKEN'}},res);
  assert.equal(res.statusCode,200);assert.equal(reads,1);
});
