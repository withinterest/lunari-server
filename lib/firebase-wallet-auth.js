export class WalletAuthError extends Error {
  constructor(code, status) { super(code); this.code = code; this.status = status; }
}
export function assertDevelopmentAuthConfiguration(env) {
  if (env.WALLET_AUTH_DEV_ENABLED !== '1' || env.WALLET_ENV !== 'development' ||
      env.FIREBASE_PROJECT_ID !== 'lunari-dev' || (env.VERCEL==='1'||env.VERCEL_ENV&&env.VERCEL_ENV!=='development') ||
      env.FIREBASE_AUTH_EMULATOR_HOST) throw new WalletAuthError('DEV_AUTH_UNAVAILABLE', 503);
}
export function createFirebaseTokenVerifier({ getAuth, env = process.env }) {
  return async token => {
    assertDevelopmentAuthConfiguration(env);
    let decoded;
    try { decoded = await (await getAuth()).verifyIdToken(token, true); }
    catch (error) {
      if (error instanceof WalletAuthError) throw error;
      if (typeof error?.code === 'string' && error.code.startsWith('auth/'))
        throw new WalletAuthError('INVALID_AUTH_TOKEN', 401);
      throw new WalletAuthError('AUTH_VERIFICATION_UNAVAILABLE', 503);
    }
    const uid = decoded?.uid;
    if (typeof uid !== 'string' || !uid.length || uid.length > 128 || uid !== uid.trim() ||
        /[\x00-\x1f\x7f]/u.test(uid) || decoded.sub !== uid ||
        decoded.aud !== env.FIREBASE_PROJECT_ID ||
        decoded.iss !== `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}` ||
        decoded.firebase?.sign_in_provider !== 'google.com' ||
        !Number.isFinite(decoded.exp) || decoded.exp * 1000 <= Date.now())
      throw new WalletAuthError('INVALID_AUTH_TOKEN', 401);
    return Object.freeze({ uid });
  };
}

async function configuredAdminAuth(env) {
  assertDevelopmentAuthConfiguration(env);
  let credential;
  try {
    let encoded = env.FIREBASE_ADMIN_SERVICE_ACCOUNT_JSON;
    if (!encoded && env.FIREBASE_ADMIN_SERVICE_ACCOUNT_FILE) {
      const { readFile } = await import('node:fs/promises');
      encoded = await readFile(env.FIREBASE_ADMIN_SERVICE_ACCOUNT_FILE, 'utf8');
    }
    const raw = JSON.parse(encoded ?? '');
    if (raw.project_id !== 'lunari-dev' || typeof raw.client_email !== 'string' ||
        typeof raw.private_key !== 'string' || !raw.private_key.includes('PRIVATE KEY')) throw new Error();
    const { initializeApp, getApps, cert } = await import('firebase-admin/app');
    const name = 'lunari-wallet-auth-dev';
    // One explicitly configured Firebase project per process/environment.
    credential = getApps().find(app => app.name === name) ?? initializeApp({
      credential: cert(raw), projectId: 'lunari-dev',
    }, name);
    const { getAuth } = await import('firebase-admin/auth');
    return getAuth(credential);
  } catch { throw new WalletAuthError('AUTH_SERVER_NOT_CONFIGURED', 503); }
}
export const verifyDevelopmentFirebaseToken = token => createFirebaseTokenVerifier({
  env: process.env, getAuth: () => configuredAdminAuth(process.env),
})(token);
