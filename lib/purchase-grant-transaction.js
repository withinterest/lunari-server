// Token hashing MUST use the SAME stable HMAC key and public.purchase_claims
// relation as legacy claims. No cross-project dedupe or automatic key rotation
// is claimed. Actual activation requires independent verification of continuity.
// Financial transaction core. Called only after authenticated Google evidence
// and connection/catalog verification. Never call the legacy claim API first.
import {WalletAuthError} from './firebase-wallet-auth.js';
import {qaDatabaseChecks as checks} from './qa-wallet-v2-reader.js';
const refuse=(code,status=503)=>{throw new WalletAuthError(code,status);};
export async function commitVerifiedPurchase({issuer,executor,uid,evidence}){
 if(typeof uid!=='string'||!uid.length||uid.length>128||uid!==uid.trim()||/[\x00-\x1f\x7f]/.test(uid)||evidence?.uid!==uid||evidence.productId!=='lunari_stars_30'||!/^[a-f0-9]{64}$/.test(evidence.tokenHash??'')||!['new','replay'].includes(evidence.consumption))refuse('PURCHASE_NOT_VERIFIED',422);
 // Consumption is part of the deterministic key because it is included in the
 // existing function's fingerprint. Token PK still enforces ONE financial grant.
 const payload={requestKey:'qa-purchase:v1:'+evidence.tokenHash+':'+evidence.consumption,productId:evidence.productId,tokenHash:evidence.tokenHash,consumption:evidence.consumption,purchaseState:'PURCHASED',orderId:evidence.orderId??null};
 let issuerBegun=false,executorBegun=false,committing=false;
 const begin=async d=>{await d.query('SET LOCAL search_path=pg_catalog,pg_temp');await d.query("SET LOCAL lock_timeout='3s'");await d.query("SET LOCAL statement_timeout='15s'");};
 try{
  await issuer.query('BEGIN READ WRITE');issuerBegun=true;await begin(issuer);
  const issue=async(op,p)=>{const token=(await issuer.query('SELECT wallet_v2_secure.issue_context($1,$2,$3,$4::jsonb) AS token',[uid,'google',op,JSON.stringify(p)])).rows[0]?.token;if(!/^[a-f0-9]{64}$/.test(token??''))refuse('PURCHASE_CONTEXT_REFUSED');return token;};
  const readToken=await issue('read',{}),purchaseToken=await issue('purchase',payload);
  committing=true;const issued=await issuer.query('COMMIT');if(issued.command!=='COMMIT')refuse('PURCHASE_COMMIT_UNCONFIRMED');issuerBegun=false;committing=false;
  await executor.query('BEGIN READ WRITE');executorBegun=true;await begin(executor);
  await executor.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))',['wallet:'+uid]);
  const read=async()=>checks.validateSnapshot((await executor.query("SELECT wallet_v2_secure.read_wallet($1,'{}'::jsonb) AS result",[readToken])).rows[0]?.result,uid);
  const before=await read();if(!before.walletExists||before.fundingState!=='active')refuse('PURCHASE_WALLET_REQUIRED',409);
  // Existing function handles claim ownership, token uniqueness, legacy-only
  // claim rejection, ledger, paid lot, movements and request idempotency together.
  const raw=(await executor.query('SELECT wallet_v2_secure.credit_purchase($1,$2::jsonb) AS result',[purchaseToken,JSON.stringify(payload)])).rows[0]?.result;
  if(raw?.ok!==true||raw.status!=='committed'||typeof raw.replay!=='boolean'||!/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(raw.transactionId??'')||raw.free!==0||raw.paid!==30||raw.total!==30||(raw.alreadyApplied!==undefined&&raw.alreadyApplied!==true))refuse('PURCHASE_RESULT_REFUSED');
  const duplicate=raw.replay||raw.alreadyApplied===true,delta=duplicate?0:30,after=await read();
  if(!after.walletExists||after.fundingState!=='active'||after.balance.free!==before.balance.free||after.balance.paid!==before.balance.paid+delta||after.balance.total!==before.balance.total+delta||BigInt(after.revision)!==BigInt(before.revision)+(duplicate?0n:1n))refuse('PURCHASE_RESULT_REFUSED');
  committing=true;const done=await executor.query('COMMIT');if(done.command!=='COMMIT')refuse('PURCHASE_COMMIT_UNCONFIRMED');executorBegun=false;committing=false;
  return{ok:true,verified:true,productId:'lunari_stars_30',status:duplicate?'already_granted':'granted',committed:true,transactionId:raw.transactionId,newlyGrantedStars:delta,completion:evidence.consumption==='new'?'consume':'already_consumed',grantApproved:true};
 }catch(e){
  if(committing)refuse('PURCHASE_COMMIT_UNCONFIRMED');
  const safe=new Set(['PURCHASE_OWNED_BY_OTHER_ACCOUNT','PURCHASE_CLAIM_REQUIRES_REVIEW','PURCHASE_ALREADY_CONSUMED','IDEMPOTENCY_CONFLICT','WALLET_NOT_REGISTERED','LEGACY_ALLOCATION_REQUIRED','WALLET_ON_HOLD']);
  if(e instanceof WalletAuthError)throw e;
  if(e?.code==='P0001'&&safe.has(e.message))refuse(e.message,409);
  refuse('PURCHASE_GRANT_UNAVAILABLE');
 }finally{
  if(executorBegun)await executor.query('ROLLBACK').catch(()=>{});
  if(issuerBegun)await issuer.query('ROLLBACK').catch(()=>{});
 }
}
