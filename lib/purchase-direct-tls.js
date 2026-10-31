import {createRequire} from 'node:module';import {readFile} from 'node:fs/promises';import tls from 'node:tls';
import {QA_PURCHASE_TARGET as t} from './purchase-qa-runtime.js';import {refuse,PURCHASE_API,sha} from './purchase-qa-policy.js';import {assertPurchasePreparationApproval} from './purchase-preparation-approval.js';
const require=createRequire(new URL('../tools/purchase-direct-runtime/package.json',import.meta.url));
export function strictChannelBindingClient(Base){
 return class extends Base{
  rejectBinding(){this.connection.emit('error',Object.assign(Error('PURCHASE_CHANNEL_BINDING_REQUIRED'),{code:'PURCHASE_CHANNEL_BINDING_REQUIRED'}));this.connection.stream?.destroy();}
  _handleAuthCleartextPassword(){this.rejectBinding();}
  _handleAuthMD5Password(){this.rejectBinding();}
  _handleAuthSASL(msg){if(this.bindingStarted||!Array.isArray(msg.mechanisms)||!msg.mechanisms.includes('SCRAM-SHA-256-PLUS')||this.connection.stream?.authorized!==true||this.connection.stream?.encrypted!==true){this.rejectBinding();return;}this.bindingStarted=true;super._handleAuthSASL(msg);}
  _handleAuthSASLContinue(msg){if(!this.bindingStarted){this.rejectBinding();return;}return super._handleAuthSASLContinue(msg);}
  _handleAuthSASLFinal(msg){if(this.saslSession?.mechanism!=='SCRAM-SHA-256-PLUS'){this.rejectBinding();return;}super._handleAuthSASLFinal(msg);this.bindingFinished=this.saslSession===null;}
  _handleReadyForQuery(msg){if(!this.bindingFinished){this.rejectBinding();return;}super._handleReadyForQuery(msg);}
 };
}
export async function loadStrictPgClient(){
 const integrity=JSON.parse(await readFile(new URL('../tools/purchase-direct-runtime/driver-integrity.json',import.meta.url),'utf8'));
 if(Object.keys(integrity).sort().join(',')!=='lib/client.js,lib/crypto/sasl.js'||Object.values(integrity).some(h=>!/^[a-f0-9]{64}$/u.test(h)))refuse('PURCHASE_PG_INTEGRITY_MANIFEST');
 for(const [name,expected] of Object.entries(integrity)){const bytes=await readFile(new URL('../tools/purchase-direct-runtime/node_modules/pg/'+name,import.meta.url));if(sha(bytes)!==expected)refuse('PURCHASE_PG_SOURCE_INTEGRITY');}
 const pkg=require('pg/package.json');if(pkg.version!=='8.23.1')refuse('PURCHASE_PG_VERSION_REFUSED');
 return strictChannelBindingClient(require('pg').Client);
}
export function assertDirectPurchaseTarget(env,scope){
 const owner=['inspect-installer','install-functions','activate-function'].includes(scope),role=owner?'neondb_owner':PURCHASE_API;
 if(!['inspect-installer','install-functions','activate-function','inspect-purchase'].includes(scope)||env.WALLET_PURCHASE_DIRECT_ENABLED!=='1'||env.WALLET_ENV!=='development'||env.FIREBASE_PROJECT_ID!=='lunari-dev'||env.NODE_ENV==='production')refuse('PURCHASE_DIRECT_DISABLED');
 for(const k of ['VERCEL','VERCEL_ENV','DATABASE_URL','WALLET_QA_DATABASE_URL','WALLET_RUNTIME_DATABASE_URL','WALLET_DEV_DATABASE_URL','WALLET_MIGRATION_DATABASE_URL','WALLET_PRODUCTION_DATABASE_URL','WALLET_PURCHASE_QA_DATABASE_URL','NODE_OPTIONS','NODE_TLS_REJECT_UNAUTHORIZED','NODE_EXTRA_CA_CERTS','PGHOST','PGPASSWORD','PGPASSFILE','PGSERVICE','PGOPTIONS','SSLKEYLOGFILE'])if(env[k]||process.env[k])refuse('PURCHASE_DIRECT_ENVIRONMENT_MIXED');
 let url;try{url=new URL(env.WALLET_PURCHASE_DIRECT_DATABASE_URL);}catch{refuse('PURCHASE_DIRECT_TARGET_REFUSED');}
 if(!['postgres:','postgresql:'].includes(url.protocol)||url.hostname!==t.host||url.pathname!=='/neondb'||decodeURIComponent(url.username)!==role||url.password||url.hash||(url.port&&url.port!=='5432')||url.searchParams.getAll('sslmode').length!==1||url.searchParams.get('sslmode')!=='verify-full'||url.searchParams.getAll('channel_binding').length!==1||url.searchParams.get('channel_binding')!=='require'||[...url.searchParams.keys()].some(k=>!['sslmode','channel_binding'].includes(k)))refuse('PURCHASE_DIRECT_TARGET_REFUSED');
 return{url,role};
}
async function metadata(env,fetcher){
 if(!env.NEON_API_KEY||typeof fetcher!=='function')refuse('PURCHASE_DIRECT_METADATA_REQUIRED');
 const base='https://console.neon.tech/api/v2/projects/'+t.projectId;
 const read=async p=>{try{const r=await fetcher(base+p,{headers:{Authorization:'Bearer '+env.NEON_API_KEY},redirect:'error',signal:AbortSignal.timeout(10000)});if(!r.ok)throw Error();return await r.json();}catch{refuse('PURCHASE_DIRECT_METADATA_FAILED');}};
 const{project}=await read(''),{branch}=await read('/branches/'+t.branchId),{endpoint}=await read('/endpoints/'+t.endpointId),listing=await read('/endpoints');
 if(project?.id!==t.projectId||project.name!==t.projectName||branch?.id!==t.branchId||branch.project_id!==t.projectId||branch.name!==t.branchName||branch.default!==false||branch.protected!==false||branch.parent_id!==t.productionBranchId||endpoint?.id!==t.endpointId||endpoint.branch_id!==t.branchId||endpoint.project_id!==t.projectId||endpoint.host!==t.host||endpoint.type!=='read_write'||listing.next_cursor||listing.pagination?.next_cursor||!Array.isArray(listing.endpoints))refuse('PURCHASE_DIRECT_METADATA_MISMATCH');
 const prod=listing.endpoints.filter(e=>e.branch_id===t.productionBranchId);if(prod.length!==1||prod[0].id!==t.productionEndpointId||prod[0].host===t.host||!listing.endpoints.some(e=>e.id===t.endpointId&&e.branch_id===t.branchId&&e.host===t.host))refuse('PURCHASE_DIRECT_PRODUCTION_MIXED');
}
// No default password provider. Caller must use hidden TTY input or an approved
// vault callback; never put a password in URL, CLI arguments or environment.
export async function openDirectPurchaseClient({env,scope,approval,approvalKey,planDigest,getPassword},deps={}){
 const{role}=assertDirectPurchaseTarget(env,scope);assertPurchasePreparationApproval(approval,{scope,planDigest},approvalKey);
 await metadata(env,deps.fetcher??fetch);if(typeof getPassword!=='function')refuse('PURCHASE_PASSWORD_PROVIDER_REQUIRED');
 const Client=deps.Client??await loadStrictPgClient();
 const db=new Client({host:t.host,port:5432,user:role,database:'neondb',password:async()=>getPassword(role),ssl:{rejectUnauthorized:true,minVersion:'TLSv1.2',servername:t.host,checkServerIdentity:tls.checkServerIdentity},enableChannelBinding:true,connectionTimeoutMillis:10000,query_timeout:15000,options:'-c default_transaction_read_only=on'});
 db.on('error',()=>{});db.on('notice',()=>{});
 try{
  await db.connect();if(db.bindingFinished!==true||db.connection.stream.authorized!==true)refuse('PURCHASE_DIRECT_BINDING_UNCONFIRMED');
  await db.query('BEGIN READ ONLY');
  const r=(await db.query("SELECT current_database() AS database,current_user AS role,session_user AS session_role,current_setting('server_version_num')::int AS version")).rows[0];
  if(!r||r.database!=='neondb'||r.role!==role||r.session_role!==role||r.version!==180006)refuse('PURCHASE_DIRECT_IDENTITY_REFUSED');await db.query('ROLLBACK');
  return{db,transport:{kind:'tls',peerHost:t.host,certificateVerified:true,channelBindingRequired:true,channelBindingVerified:true}};
 }catch{await db.end().catch(()=>{});refuse('PURCHASE_DIRECT_CONNECT_FAILED');}
}
