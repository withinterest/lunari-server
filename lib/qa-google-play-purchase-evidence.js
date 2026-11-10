import {createHmac, timingSafeEqual} from 'node:crypto';
import {evaluatePurchase} from '../api/google-play/verify.js';
import {purchaseTokenHash} from './purchase-claim-store.js';
import {WalletAuthError} from './firebase-wallet-auth.js';

export function purchaseAccountBinding(uid, secret) {
  return createHmac('sha256', secret).update('lunari-google-play-account-v1\0' + uid).digest('hex');
}

function fail(code) {
  throw new WalletAuthError(code, code === 'PURCHASE_NOT_VERIFIED' ? 422 : 503);
}

// The configured start is UTC and second-precise. Set it once at QA
// activation and keep it unchanged across retries and redeployments.
export function parseQaPurchaseStart(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(value)) return NaN;
  return parseGooglePurchaseTime(value);
}

// ProductPurchaseV2 uses RFC 3339, with up to 9 fractional digits and offsets.
// Check the calendar before Date.parse can normalize impossible dates.
function parseGooglePurchaseTime(value) {
  if (typeof value !== 'string') return NaN;
  const fields = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/u.exec(value);
  if (!fields || fields[0] !== value || fields[1].startsWith('0000-') || fields[3] === '-00:00') return NaN;
  const [, localTime, fraction = '', zone] = fields;
  const calendarMs = Date.parse(localTime + 'Z');
  if (!Number.isFinite(calendarMs) || new Date(calendarMs).toISOString().slice(0, 19) !== localTime) return NaN;
  return Date.parse(localTime + '.' + fraction.padEnd(3, '0').slice(0, 3) + zone);
}

// The Play Developer API sets this context for test purchases. Require the
// documented test payment type before passing evidence to the shared verifier.
export function createQaTestPurchaseEvidence({verifyGoogle, tokenSecret, accountSecret, purchaseStartMs}) {
  if (typeof verifyGoogle !== 'function' || !Number.isFinite(purchaseStartMs) || purchaseStartMs > Date.now()) {
    fail('VERIFIER_UNAVAILABLE');
  }
  return async (principal, body) => {
    if (principal.mode !== 'google' || body.productId !== 'lunari_stars_30' ||
        typeof body.purchaseToken !== 'string' || !body.purchaseToken.length ||
        body.purchaseToken.length > 8192 || body.purchaseToken !== body.purchaseToken.trim()) {
      fail('PURCHASE_NOT_VERIFIED');
    }
    try {
      const purchase = await verifyGoogle({packageName: 'com.lunari.app', purchaseToken: body.purchaseToken});
      const context = purchase?.testPurchaseContext;
      if (!purchase || !Object.hasOwn(purchase, 'testPurchaseContext') ||
          !context || typeof context !== 'object' || Array.isArray(context) ||
          !Object.hasOwn(context, 'fopType') || context.fopType !== 'TEST') {
        fail('PURCHASE_NOT_VERIFIED');
      }
      const completedAt = parseGooglePurchaseTime(purchase.purchaseCompletionTime);
      if (!Object.hasOwn(purchase, 'purchaseCompletionTime') || !Number.isFinite(completedAt) ||
          completedAt < purchaseStartMs || completedAt > Date.now()) {
        fail('PURCHASE_NOT_VERIFIED');
      }
      const evaluated = evaluatePurchase(purchase);
      const details = purchase.productLineItem?.[0]?.productOfferDetails;
      const binding = purchase.obfuscatedExternalAccountId;
      const expected = purchaseAccountBinding(principal.uid, accountSecret);
      if (evaluated.productId !== body.productId || evaluated.grantStars !== 30 ||
          purchase.productLineItem.length !== 1 || details?.quantity !== 1 || details.refundableQuantity !== 1 ||
          typeof binding !== 'string' || !/^[a-f0-9]{64}$/u.test(binding) ||
          !timingSafeEqual(Buffer.from(binding), Buffer.from(expected))) {
        fail('PURCHASE_NOT_VERIFIED');
      }
      const consumption = details.consumptionState;
      if (!['CONSUMPTION_STATE_YET_TO_BE_CONSUMED', 'CONSUMPTION_STATE_CONSUMED'].includes(consumption)) {
        fail('PURCHASE_NOT_VERIFIED');
      }
      return {
        uid: principal.uid,
        productId: body.productId,
        tokenHash: purchaseTokenHash(tokenSecret, body.purchaseToken),
        orderId: evaluated.googleOrderId,
        consumption: consumption === 'CONSUMPTION_STATE_CONSUMED' ? 'replay' : 'new',
      };
    } catch {
      fail('PURCHASE_NOT_VERIFIED');
    }
  };
}
