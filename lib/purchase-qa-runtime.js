import {collectPurchaseBoundary,validatePurchaseBoundary,refuse,PURCHASE_API} from './purchase-qa-policy.js';
export const QA_PURCHASE_TARGET=Object.freeze({projectId:'round-credit-14510227',projectName:'lunari-wallet-production-check',branchId:'br-restless-grass-b3odflam',branchName:'qa-wallet-integration',endpointId:'ep-silent-leaf-b3xp84bu',host:'ep-silent-leaf-b3xp84bu.c-4.ap-southeast-1.aws.neon.tech',database:'neondb',productionBranchId:'br-ancient-glitter-b3h67y5r',productionEndpointId:'ep-wispy-shape-b3p581us'});
export function assertPurchaseQaConfiguration(env){
 if(env.WALLET_PURCHASE_QA_ENABLED!=='1'||env.WALLET_ENV!=='development'||env.WALLET_AUTH_DEV_ENABLED!=='1'||env.FIREBASE_PROJECT_ID!=='lunari-dev'||env.NODE_ENV==='production')refuse('PURCHASE_QA_DISABLED');
 for(const k of ['VERCEL','VERCEL_ENV','DATABASE_URL','WALLET_RUNTIME_DATABASE_URL','WALLET_DEV_DATABASE_URL','WALLET_QA_DATABASE_URL','WALLET_MIGRATION_DATABASE_URL','WALLET_PRODUCTION_DATABASE_URL','WALLET_PURCHASE_LOCAL_DATABASE_URL','PGHOST','PGOPTIONS','PGSERVICE','NODE_OPTIONS','NODE_TLS_REJECT_UNAUTHORIZED','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SSLKEYLOGFILE','FIREBASE_AUTH_EMULATOR_HOST'])if(env[k])refuse('PURCHASE_ENVIRONMENT_MIXED');
 let u,username;try{u=new URL(env.WALLET_PURCHASE_QA_DATABASE_URL);username=decodeURIComponent(u.username);}catch{refuse('PURCHASE_QA_URL_REFUSED');}
 if(!['postgres:','postgresql:'].includes(u.protocol)||u.hostname!==QA_PURCHASE_TARGET.host||u.pathname!=='/neondb'||username!==PURCHASE_API||!u.password||u.hash||(u.port&&u.port!=='5432')||u.searchParams.getAll('sslmode').length!==1||u.searchParams.get('sslmode')!=='verify-full'||[...u.searchParams.keys()].some(k=>!['sslmode','channel_binding'].includes(k)))refuse('PURCHASE_QA_URL_REFUSED');
 if(u.searchParams.has('channel_binding')&&(u.searchParams.getAll('channel_binding').length!==1||u.searchParams.get('channel_binding')!=='require'))refuse('PURCHASE_CHANNEL_BINDING_REFUSED');
 return u;
}
export async function verifyPurchaseQaMetadata(env,fetcher){
 assertPurchaseQaConfiguration(env);if(typeof fetcher!=='function'||!env.NEON_API_KEY)refuse('PURCHASE_METADATA_REQUIRED');
 const t=QA_PURCHASE_TARGET,base='https://console.neon.tech/api/v2/projects/'+t.projectId;
 async function read(path){try{const r=await fetcher(base+path,{headers:{Authorization:'Bearer '+env.NEON_API_KEY},redirect:'error',signal:AbortSignal.timeout(10000)});if(!r.ok)refuse('PURCHASE_METADATA_FAILED');return await r.json();}catch{refuse('PURCHASE_METADATA_FAILED');}}
 const {project}=await read(''),{branch}=await read('/branches/'+t.branchId),{endpoint}=await read('/endpoints/'+t.endpointId),list=await read('/endpoints');
 if(project?.id!==t.projectId||project.name!==t.projectName||branch?.id!==t.branchId||branch.project_id!==t.projectId||branch.name!==t.branchName||branch.parent_id!==t.productionBranchId||branch.default!==false||branch.protected!==false||endpoint?.id!==t.endpointId||endpoint.project_id!==t.projectId||endpoint.branch_id!==t.branchId||endpoint.host!==t.host||endpoint.type!=='read_write'||list.pagination?.next_cursor||list.next_cursor||!Array.isArray(list.endpoints))refuse('PURCHASE_METADATA_MISMATCH');
 const prod=list.endpoints.filter(e=>e.branch_id===t.productionBranchId);
 if(prod.length!==1||prod[0].id!==t.productionEndpointId||prod[0].host===t.host||!list.endpoints.some(e=>e.id===t.endpointId&&e.branch_id===t.branchId&&e.host===t.host))refuse('PURCHASE_PRODUCTION_NOT_SEPARATED');
 return{ok:true,target:t,transportVerified:false};
}
export function validatePurchaseTransportAndSession(transport,row){
 if(transport?.certificateVerified!==true||transport.peerHost!==QA_PURCHASE_TARGET.host||!['tls','wss'].includes(transport.kind)||transport.channelBindingRequired&&transport.channelBindingVerified!==true)refuse('PURCHASE_TLS_NOT_VERIFIED');
 if(!row||row.database!=='neondb'||row.role!==PURCHASE_API||row.session_role!==PURCHASE_API||row.version!==180006||row.safe_path!==true||row.no_temp!==true||row.read_only!==true)refuse('PURCHASE_QA_SESSION_UNSAFE');
 return{ok:true};
}
export const PURCHASE_SESSION_SQL=`SELECT current_database() AS database,current_user AS role,session_user AS session_role,
 current_setting('server_version_num')::int AS version,current_setting('search_path')='pg_catalog, pg_temp' AS safe_path,
 pg_catalog.pg_my_temp_schema()=0 AS no_temp,current_setting('transaction_read_only')='on' AS read_only`;
// No default network connector and no apply function. Caller must provide a reviewed,
// certificate-verifying adapter. Metadata alone cannot authorize a DB connection.
export async function inspectPurchaseQaRuntime({env,fetcher,openVerifiedClient,plan,archiveFunctions,active=false}){
 await verifyPurchaseQaMetadata(env,fetcher);
 if(typeof openVerifiedClient!=='function')refuse('PURCHASE_CONNECTOR_NOT_IMPLEMENTED');
 let db,begun=false;try{
 const opened=await openVerifiedClient({url:assertPurchaseQaConfiguration(env),target:QA_PURCHASE_TARGET});db=opened.db;
 await db.query('BEGIN READ ONLY');begun=true;await db.query('SET LOCAL search_path=pg_catalog, pg_temp');
 validatePurchaseTransportAndSession({...opened.transport,channelBindingRequired:assertPurchaseQaConfiguration(env).searchParams.get('channel_binding')==='require'},(await db.query(PURCHASE_SESSION_SQL)).rows[0]);
 const result=validatePurchaseBoundary(await collectPurchaseBoundary(db),plan,{archiveFunctions,active});await db.query('ROLLBACK');begun=false;
 return result;
 }catch(e){if(begun)try{await db.query('ROLLBACK');}catch{refuse('PURCHASE_INSPECTION_ROLLBACK_UNCONFIRMED');}refuse('PURCHASE_RUNTIME_INSPECTION_FAILED');}
 finally{if(db)try{await db.end();}catch{refuse('PURCHASE_INSPECTION_CLOSE_FAILED');}}
}
