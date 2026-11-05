import {createHash} from 'node:crypto';
import {WalletAuthError} from './firebase-wallet-auth.js';
export const QA_UNLOCK_CONTENT='qa_wallet_unlock_2stars_v1';
export const QA_UNLOCK_COST=2;
export const qaUnlockPins=Object.freeze({"issue_unlock_context":{"bodyHash":"85dc366daf9d50f490a1c39033663577f3af45bf4369dcb0312c82b3b6984bb1","args":"u text, p jsonb"},"unlock_content_2stars":{"bodyHash":"f6a4a2e70b1346da83ffb56fe974a644d5973486efc0682b4e12bb8021e6b484","args":"token text, p jsonb"}});
export const QA_UNLOCK_FUNCTION_SQL=`SELECT p.proname AS name,p.prosrc AS body,p.prosecdef AS definer,p.proconfig,p.prokind,l.lanname,pg_catalog.pg_get_function_identity_arguments(p.oid) AS args,pg_catalog.pg_get_userbyid(p.proowner)::text AS owner,
 has_function_privilege($1,p.oid,'EXECUTE') AS executable,EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE n.nspname='wallet_v2_qa_test'`;
export const QA_UNLOCK_SCHEMA_SQL=`SELECT pg_catalog.pg_get_userbyid(n.nspowner)::text AS owner,has_schema_privilege($1,n.oid,'USAGE') AS usable,
 EXISTS(SELECT 1 FROM aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE a.grantee=0 AND a.privilege_type IN('USAGE','CREATE')) AS public_access
 FROM pg_catalog.pg_namespace n WHERE n.nspname='wallet_v2_qa_test'`;
export function assertQaUnlockFunctions(rows,kind){
 if(!['issuer','executor'].includes(kind))throw new WalletAuthError('QA_UNLOCK_BOUNDARY_REFUSED',503);
 const expected=kind==='issuer'?'issue_unlock_context':'unlock_content_2stars';
 if(!Array.isArray(rows)||rows.length!==2)throw new WalletAuthError('QA_UNLOCK_NOT_INSTALLED',503);
 for(const [name,pin]of Object.entries(qaUnlockPins)){
  const found=rows.filter(r=>r.name===name),f=found[0];
  if(found.length!==1||f.owner!=='lunari_wallet_v2_fn_owner_qa'||f.prokind!=='f'||f.lanname!=='plpgsql'||f.definer!==true||f.args!==pin.args||f.public_execute!==false||f.executable!==(name===expected)||JSON.stringify(f.proconfig)!==JSON.stringify(['search_path=pg_catalog, pg_temp'])||typeof f.body!=='string'||createHash('sha256').update(f.body).digest('hex')!==pin.bodyHash)throw new WalletAuthError('QA_UNLOCK_BOUNDARY_REFUSED',503);
 }
}
