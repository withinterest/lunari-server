import {CANONICAL_TABLES,inspectPrototype,validatePrototype,preservationStamp,digest} from './wallet-qa-catalog.js';
import {collectQaV2Security,validateQaV2Security} from './wallet-qa-security-v2.js';
import {installedQaV2Options} from './wallet-qa-plan-v2.js';
import {qaFail} from './wallet-qa-target.js';
// OID-independent schema evidence. Raw definitions stay in memory, never CLI logs.
export const INSTALLED_SQL={
 relations:`SELECT c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,c.relispartition,pg_catalog.pg_get_userbyid(c.relowner)::text AS owner FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN('r','S') ORDER BY c.relname`,
 columns:`SELECT c.relname,a.attnum,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod) AS type,a.attnotnull,a.attidentity,a.attgenerated,pg_catalog.pg_get_expr(d.adbin,d.adrelid) AS default_sql FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='public' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`,
 constraints:`SELECT c.relname,k.conname,k.contype,k.condeferrable,k.condeferred,k.convalidated,pg_catalog.pg_get_constraintdef(k.oid,true) AS definition FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname,k.conname`,
 indexes:`SELECT c.relname,ic.relname AS name,pg_catalog.pg_get_userbyid(ic.relowner)::text AS owner,i.indisvalid,i.indisready,i.indislive,pg_catalog.pg_get_indexdef(i.indexrelid) AS definition FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid WHERE n.nspname='public' ORDER BY c.relname,ic.relname`,
 triggers:`SELECT c.relname,t.tgname,t.tgenabled,t.tgisinternal,pg_catalog.pg_get_triggerdef(t.oid,true) AS definition FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal ORDER BY c.relname,t.tgname`,
 sequences:`SELECT c.relname,s.seqstart::text,s.seqincrement::text,s.seqmax::text,s.seqmin::text,s.seqcache::text,s.seqcycle FROM pg_catalog.pg_sequence s JOIN pg_catalog.pg_class c ON c.oid=s.seqrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname`
};
export async function collectInstalledShapeV2(db){const result={};for(const [k,sql] of Object.entries(INSTALLED_SQL)){const r=(await db.query(sql)).rows;if(!Array.isArray(r))qaFail('QA_V2_INSTALLED_EVIDENCE_INVALID');result[k]=r;}return result;}
export function assertInstalledShapeV2(actual,reference){
 if(!reference||digest(actual)!==digest(reference))qaFail('QA_V2_INSTALLED_SCHEMA_MISMATCH');
}
export function archiveDependencyStampV2(s){
 const roots=new Set([...s.relations,...s.functions].map(r=>r.oid));
 // The only expected dependency change is each moved root's namespace edge.
 // Object OIDs and all non-namespace edges must remain byte-for-byte identical.
 return digest(s.dependencies.map(({dependent,referenced,...d})=>({...d,
  refobjid:d.refclassid==='2615'&&roots.has(d.objid)?'moved-root-namespace':d.refobjid})));
}
export async function verifyInstalledV2(db,before,plan,reference){
 const after=await inspectPrototype(db,'wallet_prototype_v1');validatePrototype(after);
 if(preservationStamp(after)!==preservationStamp(before))qaFail('QA_V2_ARCHIVE_PRESERVATION_FAILED');
 if(archiveDependencyStampV2(after)!==archiveDependencyStampV2(before))qaFail('QA_V2_ARCHIVE_DEPENDENCIES_CHANGED');
 const q=(await db.query(`SELECT /* qa-v2:quarantine */ to_regclass('public.star_transactions') IS NULL AS table_absent,
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname='process_star_transaction') AS function_absent,
 NOT pg_catalog.has_schema_privilege($1,'wallet_prototype_v1','USAGE') AS api_denied,
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a WHERE n.nspname='wallet_prototype_v1' AND a.grantee=0 AND a.privilege_type IN('USAGE','CREATE')) AS public_denied`,[plan.pins.apiRole])).rows;
 if(q.length!==1||!['table_absent','function_absent','api_denied','public_denied'].every(k=>q[0][k]===true))qaFail('QA_V2_ARCHIVE_NOT_QUARANTINED');
 const security=validateQaV2Security(await collectQaV2Security(db,plan.pins),installedQaV2Options(plan,before));
 assertInstalledShapeV2(await collectInstalledShapeV2(db),reference);
 for(const table of CANONICAL_TABLES){const r=(await db.query('SELECT count(*)::text AS count FROM public.'+table)).rows;if(r.length!==1||r[0].count!=='0')qaFail('QA_V2_UNEXPECTED_DATA');}
 return {canonicalTableCount:13,prototypePreserved:true,legacyFunctionEnabled:false,security};
}
