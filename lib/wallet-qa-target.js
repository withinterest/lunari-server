import {assertInspectionApproval} from './wallet-qa-inspection-approval.js';
// Separate QA provisioner. Existing runtime guards are deliberately untouched.
export class WalletQaError extends Error {
  constructor(code) { super(code); this.code = code; }
}
export const qaFail = code => { throw new WalletQaError(code); };
const OLD_PROJECT = 'solitary-leaf-54047628';
const OLD_ENDPOINTS = ['ep-holy-forest-b3kcmobp', 'ep-spring-block-b3avr3yz'];
const present = v => typeof v === 'string' && v.length > 0 && v === v.trim();
export function assertQaTarget(pins, env, access) {
  const inspection=access?.purpose==='inspect-prototype';
  if(access!==undefined&&(!inspection||Object.keys(access).length!==2||!Object.hasOwn(access,'inspectionApproval')))qaFail('QA_ACCESS_SCOPE_REFUSED');
  if (!pins || !(inspection?['review-required','approved'].includes(pins.status):pins.status==='approved') || pins.projectName !== 'lunari-wallet-production-check' ||
      pins.branchName !== 'qa-wallet-integration' || pins.database !== 'neondb' ||
      pins.apiRole !== 'lunari_wallet_api_check' || !present(pins.projectId) || pins.projectId === OLD_PROJECT ||
      !/^[a-z0-9-]+$/u.test(pins.projectId) || !/^br-[a-z0-9-]+$/u.test(pins.branchId ?? '') ||
      !/^br-[a-z0-9-]+$/u.test(pins.productionBranchId ?? '') || pins.branchId === pins.productionBranchId ||
      !/^ep-[a-z0-9-]+$/u.test(pins.endpointId ?? '') || OLD_ENDPOINTS.includes(pins.endpointId) ||
      !Array.isArray(pins.productionEndpointIds) || !pins.productionEndpointIds.length ||
      pins.productionEndpointIds.some(v => !/^ep-[a-z0-9-]+$/u.test(v) || v === pins.endpointId) ||
      !/^[a-z_][a-z0-9_]{0,62}$/u.test(pins.migrationRole ?? '') || pins.migrationRole === pins.apiRole ||
      !present(pins.endpointHost) || !pins.endpointHost.startsWith(pins.endpointId + '.') ||
      !/^[a-z0-9.-]+\.neon\.tech$/u.test(pins.endpointHost)) qaFail('QA_TARGET_NOT_APPROVED');
  if(inspection)assertInspectionApproval(access.inspectionApproval,pins,env);
  if (env.WALLET_QA_MODE !== 'qa' || env.NODE_ENV === 'production' ||
      ['VERCEL', 'VERCEL_ENV', 'DATABASE_URL', 'WALLET_DEV_DATABASE_URL', 'WALLET_RUNTIME_DATABASE_URL',
       'WALLET_PRODUCTION_DATABASE_URL', 'WALLET_PRODUCTION_READONLY_DATABASE_URL', 'WALLET_MIGRATION_DATABASE_URL',
       'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_OPTIONS', 'PGOPTIONS', 'PGSERVICE', 'PGSERVICEFILE', 'SSLKEYLOGFILE',
       'NODE_USE_ENV_PROXY', 'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY'].some(k => !!env[k])) qaFail('QA_ENVIRONMENT_REFUSED');
  if (!present(env.NEON_API_KEY) || !present(env.WALLET_QA_DATABASE_URL)) qaFail('QA_CREDENTIALS_MISSING');
  let url;
  try { url = new URL(env.WALLET_QA_DATABASE_URL); } catch { qaFail('QA_DATABASE_URL_REFUSED'); }
  let username;try{username=decodeURIComponent(url.username);}catch{qaFail('QA_DATABASE_URL_REFUSED');}
  if (!['postgres:', 'postgresql:'].includes(url.protocol) || url.hostname !== pins.endpointHost ||
      url.pathname !== '/neondb' || (url.port && url.port !== '5432') || url.hash || !url.password ||
      username !== pins.migrationRole || url.searchParams.get('sslmode') !== 'verify-full' ||
      [...url.searchParams.keys()].some(k => !['sslmode', 'channel_binding'].includes(k))) qaFail('QA_DATABASE_URL_REFUSED');
  return url;
}
export async function verifyQaTarget(pins, env, fetcher = fetch, access) {
  const url = assertQaTarget(pins, env, access);
  const base = 'https://console.neon.tech/api/v2/projects/' + encodeURIComponent(pins.projectId);
  async function read(suffix) {
    try {
      const response = await fetcher(base + suffix, {headers:{Authorization:'Bearer ' + env.NEON_API_KEY},
        redirect:'error', signal:AbortSignal.timeout(10000)});
      if (!response.ok) qaFail('QA_METADATA_UNAVAILABLE');
      return await response.json();
    } catch { qaFail('QA_METADATA_UNAVAILABLE'); }
  }
  const {project} = await read('');
  const {branch:qa} = await read('/branches/' + encodeURIComponent(pins.branchId));
  const {branch:production} = await read('/branches/' + encodeURIComponent(pins.productionBranchId));
  const {endpoint} = await read('/endpoints/' + encodeURIComponent(pins.endpointId));
  const listing = await read('/endpoints');
  if(listing.pagination?.next_cursor || listing.next_cursor)qaFail('QA_METADATA_INCOMPLETE');
  const {endpoints} = listing;
  if (project?.id !== pins.projectId || project.name !== pins.projectName ||
      qa?.id !== pins.branchId || qa.name !== pins.branchName || qa.project_id !== pins.projectId ||
      qa.default !== false || qa.protected !== false || qa.parent_id !== pins.productionBranchId ||
      production?.id !== pins.productionBranchId || production.name !== 'production' ||
      production.project_id !== pins.projectId || production.default !== true ||
      endpoint?.id !== pins.endpointId || endpoint.branch_id !== pins.branchId || endpoint.project_id !== pins.projectId ||
      endpoint.host !== url.hostname || endpoint.type !== 'read_write' || !Array.isArray(endpoints)) qaFail('QA_METADATA_MISMATCH');
  const prodIds = endpoints.filter(e => e.branch_id === pins.productionBranchId).map(e => e.id).sort();
  if (JSON.stringify(prodIds) !== JSON.stringify([...pins.productionEndpointIds].sort()) ||
      !endpoints.some(e => e.id === pins.endpointId && e.branch_id === pins.branchId && e.host === pins.endpointHost) ||
      endpoints.some(e => e.branch_id === pins.productionBranchId && (e.id === pins.endpointId || e.host === pins.endpointHost))) qaFail('QA_PRODUCTION_SEPARATION_FAILED');
  assertQaTarget(pins,env,access);
  return {connectionString:url.toString(), branchId:pins.branchId};
}
export async function openQaClient(pins, env, access) {
  const target = await verifyQaTarget(pins, env, undefined, access);
  if (typeof globalThis.WebSocket !== 'function' || process.env.NODE_TLS_REJECT_UNAUTHORIZED || process.env.NODE_OPTIONS)
    qaFail('QA_CERTIFICATE_VERIFICATION_REQUIRED');
  const {Client} = await import('@neondatabase/serverless');
  const db = new Client({connectionString:target.connectionString, connectionTimeoutMillis:10000, query_timeout:15000,
    application_name:'lunari_qa_baseline_provisioner',
    ...(access?.purpose==='inspect-prototype'?{options:'-c default_transaction_read_only=on'}:{})});
  // Certificate-verified WSS. Disables nested PG TLS, never network TLS validation.
  db.neonConfig.webSocketConstructor = globalThis.WebSocket;
  db.neonConfig.useSecureWebSocket = true;
  db.neonConfig.forceDisablePgSSL = true;
  db.neonConfig.pipelineConnect = false;
  db.neonConfig.wsProxy = (host, port) => {
    if (host !== pins.endpointHost || String(port) !== '5432') qaFail('QA_TRANSPORT_TARGET_MISMATCH');
    return pins.endpointHost + '/v2';
  };
  db.on('notice', () => {}); db.on('error', () => {});
  try { await db.connect(); return db; }
  catch { await db.end().catch(() => {}); qaFail('QA_DATABASE_UNAVAILABLE'); }
}
