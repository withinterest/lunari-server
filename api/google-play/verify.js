import {
  assertDatabaseUrl,
  assertPurchaseTokenHmacSecret,
  ClaimConfigurationError,
  ClaimStorageError,
  claimPurchaseWithNeon,
  purchaseTokenHash,
  validateClaimantId,
} from "../../lib/purchase-claim-store.js";

const ALLOWED_PACKAGE_NAME = "com.lunari.app";
const ALLOWED_PRODUCT_ID = "lunari_stars_30";
const GRANT_STARS = 30;
const ANDROID_PUBLISHER_SCOPE =
  "https://www.googleapis.com/auth/androidpublisher";
const CREDENTIAL_ENV_NAME = "GOOGLE_PLAY_SERVICE_ACCOUNT_JSON";
const DATABASE_ENV_NAME = "DATABASE_URL";
const HMAC_SECRET_ENV_NAME = "PURCHASE_TOKEN_HMAC_SECRET";

function response(res, status, payload) {
  return res.status(status).json(payload);
}

function failure(res, status, code, { verified = false } = {}) {
  return response(res, status, {
    ok: false,
    verified,
    grantApproved: false,
    code,
  });
}

export function parseServiceAccount(rawValue) {
  if (typeof rawValue !== "string" || rawValue.trim() === "") {
    throw new VerificationError("SERVER_CONFIG_ERROR", 500);
  }

  let credentials;
  try {
    credentials = JSON.parse(rawValue);
  } catch (_) {
    throw new VerificationError("SERVER_CONFIG_ERROR", 500);
  }

  if (
    !credentials ||
    typeof credentials !== "object" ||
    typeof credentials.client_email !== "string" ||
    credentials.client_email.trim() === "" ||
    typeof credentials.private_key !== "string" ||
    credentials.private_key.trim() === "" ||
    typeof credentials.private_key_id !== "string" ||
    credentials.private_key_id.trim() === ""
  ) {
    throw new VerificationError("SERVER_CONFIG_ERROR", 500);
  }

  return credentials;
}

export function evaluatePurchase(purchase) {
  const state = purchase?.purchaseStateContext?.purchaseState;

  if (state === "PENDING") {
    throw new VerificationError("PURCHASE_PENDING", 409);
  }
  if (state !== "PURCHASED") {
    throw new VerificationError("PURCHASE_NOT_VERIFIED", 422);
  }

  const lineItems = Array.isArray(purchase?.productLineItem)
    ? purchase.productLineItem
    : [];
  const targetLineItem = lineItems.find(
    (lineItem) => lineItem?.productId === ALLOWED_PRODUCT_ID,
  );

  if (!targetLineItem) {
    throw new VerificationError("PRODUCT_MISMATCH", 422);
  }

  // ProductPurchaseV2 reports zero refundable quantity after a full refund.
  // Missing values are tolerated because older valid purchases may omit it.
  if (targetLineItem.productOfferDetails?.refundableQuantity === 0) {
    throw new VerificationError("PURCHASE_REFUNDED", 422);
  }

  return {
    productId: ALLOWED_PRODUCT_ID,
    grantStars: GRANT_STARS,
    purchaseState: "PURCHASED",
    googleOrderId:
      typeof purchase?.orderId === "string" && purchase.orderId.trim() !== ""
        ? purchase.orderId
        : null,
  };
}

export async function verifyPurchaseWithGoogle({
  packageName,
  purchaseToken,
  credentials,
}) {
  const { google } = await import("googleapis");
  const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: [ANDROID_PUBLISHER_SCOPE],
  });
  const androidPublisher = google.androidpublisher({
    version: "v3",
    auth,
  });
  const result =
    await androidPublisher.purchases.productsv2.getproductpurchasev2({
      packageName,
      token: purchaseToken,
    });
  return result.data;
}

function googleErrorToVerificationError(error) {
  const status = Number(error?.response?.status ?? error?.code);

  if (status === 400 || status === 404) {
    return new VerificationError("PURCHASE_NOT_FOUND", 404);
  }
  if (status === 401 || status === 403) {
    return new VerificationError("GOOGLE_API_PERMISSION_ERROR", 502);
  }
  if (status === 408 || status === 429 || status >= 500) {
    return new VerificationError("GOOGLE_API_UNAVAILABLE", 503);
  }
  return new VerificationError("PURCHASE_VERIFICATION_FAILED", 502);
}

function safeLog(logger, code) {
  if (logger && typeof logger.error === "function") {
    logger.error(`[google-play-verify] ${code}`);
  }
}

function parseRequestBody(body) {
  if (body == null) return null;
  if (typeof body === "string") {
    try {
      return JSON.parse(body);
    } catch (_) {
      return null;
    }
  }
  return typeof body === "object" && !Array.isArray(body) ? body : null;
}

export function createVerifyHandler({
  verifyPurchase = verifyPurchaseWithGoogle,
  claimPurchase = claimPurchaseWithNeon,
  env = process.env,
  logger = console,
} = {}) {
  return async function handler(req, res) {
    if (req.method !== "POST") {
      res.setHeader?.("Allow", "POST");
      return failure(res, 405, "METHOD_NOT_ALLOWED");
    }

    const body = parseRequestBody(req.body);
    if (!body) return failure(res, 400, "INVALID_REQUEST");

    const packageName =
      typeof body.packageName === "string" ? body.packageName.trim() : "";
    const productId =
      typeof body.productId === "string" ? body.productId.trim() : "";
    const purchaseToken =
      typeof body.purchaseToken === "string" ? body.purchaseToken.trim() : "";
    const claimantId =
      typeof body.claimantId === "string" ? body.claimantId.trim() : "";

    if (packageName !== ALLOWED_PACKAGE_NAME) {
      return failure(res, 403, "PACKAGE_NOT_ALLOWED");
    }
    if (productId !== ALLOWED_PRODUCT_ID) {
      return failure(res, 403, "PRODUCT_NOT_ALLOWED");
    }
    if (!purchaseToken) {
      return failure(res, 400, "MISSING_PURCHASE_TOKEN");
    }
    if (!claimantId) {
      return failure(res, 400, "MISSING_CLAIMANT_ID");
    }
    if (!validateClaimantId(claimantId)) {
      return failure(res, 400, "INVALID_CLAIMANT_ID");
    }

    let credentials;
    try {
      credentials = parseServiceAccount(env[CREDENTIAL_ENV_NAME]);
      assertDatabaseUrl(env[DATABASE_ENV_NAME]);
      assertPurchaseTokenHmacSecret(env[HMAC_SECRET_ENV_NAME]);
    } catch (error) {
      const safeError =
        error instanceof VerificationError ||
        error instanceof ClaimConfigurationError
          ? error
          : new VerificationError("SERVER_CONFIG_ERROR", 500);
      safeLog(logger, safeError.code);
      return failure(res, 500, safeError.code);
    }

    try {
      const purchase = await verifyPurchase({
        packageName: ALLOWED_PACKAGE_NAME,
        purchaseToken,
        credentials,
      });
      const verifiedPurchase = evaluatePurchase(purchase);
      const tokenHash = purchaseTokenHash(
        env[HMAC_SECRET_ENV_NAME],
        purchaseToken,
      );
      const claim = await claimPurchase({
        databaseUrl: env[DATABASE_ENV_NAME],
        tokenHash,
        packageName: ALLOWED_PACKAGE_NAME,
        productId: ALLOWED_PRODUCT_ID,
        claimantId,
        grantStars: GRANT_STARS,
        purchaseState: verifiedPurchase.purchaseState,
        googleOrderId: verifiedPurchase.googleOrderId,
      });

      if (!claim.sameClaimant) {
        return failure(res, 409, "ALREADY_CLAIMED", { verified: true });
      }

      return response(res, 200, {
        ok: true,
        verified: true,
        grantApproved: true,
        claimed: true,
        idempotentReplay: claim.idempotentReplay,
        claimId: claim.claimId,
        productId: verifiedPurchase.productId,
        grantStars: verifiedPurchase.grantStars,
        status: "purchased",
      });
    } catch (error) {
      if (error instanceof ClaimStorageError) {
        safeLog(logger, error.code);
        return failure(res, 503, error.code, { verified: true });
      }
      const safeError =
        error instanceof VerificationError
          ? error
          : googleErrorToVerificationError(error);
      safeLog(logger, safeError.code);
      return failure(res, safeError.status, safeError.code);
    }
  };
}

export class VerificationError extends Error {
  constructor(code, status) {
    super(code);
    this.name = "VerificationError";
    this.code = code;
    this.status = status;
  }
}

export default createVerifyHandler();

