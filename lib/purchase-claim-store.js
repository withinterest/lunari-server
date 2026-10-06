import { createHmac, randomUUID } from "node:crypto";

const MIN_HMAC_SECRET_LENGTH = 32;
const CLAIMANT_ID_PATTERN = /^[A-Za-z0-9._:-]{16,128}$/;

export class ClaimConfigurationError extends Error {
  constructor(code) {
    super(code);
    this.name = "ClaimConfigurationError";
    this.code = code;
  }
}

export class ClaimStorageError extends Error {
  constructor() {
    super("CLAIM_STORAGE_UNAVAILABLE");
    this.name = "ClaimStorageError";
    this.code = "CLAIM_STORAGE_UNAVAILABLE";
  }
}

export function validateClaimantId(value) {
  return typeof value === "string" && CLAIMANT_ID_PATTERN.test(value);
}

export function assertPurchaseTokenHmacSecret(secret) {
  if (
    typeof secret !== "string" ||
    secret.trim().length < MIN_HMAC_SECRET_LENGTH
  ) {
    throw new ClaimConfigurationError("SERVER_CONFIG_ERROR");
  }
}

export function purchaseTokenHash(secret, purchaseToken) {
  assertPurchaseTokenHmacSecret(secret);
  return createHmac("sha256", secret).update(purchaseToken).digest("hex");
}

export function assertDatabaseUrl(databaseUrl) {
  if (typeof databaseUrl !== "string" || databaseUrl.trim() === "") {
    throw new ClaimConfigurationError("DB_CONFIG_ERROR");
  }
}

export async function claimPurchaseWithNeon({
  databaseUrl,
  tokenHash,
  packageName,
  productId,
  claimantId,
  grantStars,
  purchaseState,
  googleOrderId,
}) {
  assertDatabaseUrl(databaseUrl);
  const proposedClaimId = randomUUID();

  try {
    const { neon } = await import("@neondatabase/serverless");
    const sql = neon(databaseUrl);
    const rows = await sql.query(
      `INSERT INTO purchase_claims (
         token_hash,
         package_name,
         product_id,
         claimant_id,
         grant_stars,
         purchase_state,
         google_order_id,
         claim_id
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::uuid)
       ON CONFLICT (token_hash) DO UPDATE
         SET token_hash = EXCLUDED.token_hash
       RETURNING
         claim_id::text AS "claimId",
         claimant_id AS "claimantId",
         package_name AS "packageName",
         product_id AS "productId",
         grant_stars AS "grantStars",
         purchase_state AS "purchaseState"`,
      [
        tokenHash,
        packageName,
        productId,
        claimantId,
        grantStars,
        purchaseState,
        googleOrderId ?? null,
        proposedClaimId,
      ],
    );

    const row = rows[0];
    if (
      !row ||
      row.packageName !== packageName ||
      row.productId !== productId ||
      Number(row.grantStars) !== grantStars ||
      row.purchaseState !== purchaseState
    ) {
      throw new ClaimStorageError();
    }

    return {
      claimId: row.claimId,
      sameClaimant: row.claimantId === claimantId,
      idempotentReplay: row.claimId !== proposedClaimId,
    };
  } catch (error) {
    if (error instanceof ClaimStorageError) throw error;
    throw new ClaimStorageError();
  }
}
