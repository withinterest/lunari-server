import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  assertDatabaseUrl,
  purchaseTokenHash,
  validateClaimantId,
} from "../lib/purchase-claim-store.js";

test("claimant ids accept installation-safe identifiers only", () => {
  assert.equal(validateClaimantId("550e8400-e29b-41d4-a716-446655440000"), true);
  assert.equal(validateClaimantId("installation_1234.safe"), true);
  assert.equal(validateClaimantId("short"), false);
  assert.equal(validateClaimantId("unsafe claimant!"), false);
  assert.equal(validateClaimantId("a".repeat(129)), false);
});

test("purchase token HMAC is deterministic and never equals the token", () => {
  const secret = "unit-test-secret-with-at-least-32-characters";
  const token = "sensitive-purchase-token";
  const first = purchaseTokenHash(secret, token);
  const second = purchaseTokenHash(secret, token);

  assert.equal(first, second);
  assert.match(first, /^[0-9a-f]{64}$/);
  assert.notEqual(first, token);
});

test("HMAC secret and database URL must be configured", () => {
  assert.throws(() => purchaseTokenHash("short", "token"), {
    code: "SERVER_CONFIG_ERROR",
  });
  assert.throws(() => assertDatabaseUrl(""), { code: "DB_CONFIG_ERROR" });
});

test("migration has claim constraints and no destructive SQL", async () => {
  const migration = await readFile(
    new URL("../migrations/001_create_purchase_claims.sql", import.meta.url),
    "utf8",
  );

  assert.match(migration, /token_hash CHAR\(64\) PRIMARY KEY/i);
  assert.match(migration, /claim_id UUID NOT NULL UNIQUE/i);
  assert.match(migration, /CHECK \(grant_stars > 0\)/i);
  assert.match(migration, /CHECK \(purchase_state = 'PURCHASED'\)/i);
  assert.doesNotMatch(migration, /\b(DROP|TRUNCATE|DELETE)\b/i);
});
