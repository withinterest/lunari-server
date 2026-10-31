import {qaFail} from './wallet-qa-target.js';

// One fixed predicate definition feeds both catalog SQL and offline regression
// fixtures. No user-supplied identifier or predicate is interpolated into SQL.
const TOAST_RULES=[
 ['parent.relkind','=','r'],['parent.relpersistence','=','p'],
 ['parent.reltoastrelid','<>','0'],['parent.reltoastrelid','=',{field:'toast.oid'}],
 ['toast_ns.nspname','=','pg_toast'],['toast.relkind','=','t'],
 ['toast.relowner','=',{field:'parent.relowner'}],['toast.relpersistence','=','p'],
 ['toast.relrowsecurity','=',false],['toast.relforcerowsecurity','=',false],['toast.relispartition','=',false]
];
const TOAST_INDEX_RULES=[
 ['i.indrelid','=',{field:'toast.oid'}],['i.indexrelid','=',{field:'idx.oid'}],
 ['idx_ns.nspname','=','pg_toast'],['idx.relkind','=','i'],['idx.relpersistence','=','p'],
 ['idx.relowner','=',{field:'parent.relowner'}],['idx.relispartition','=',false],
 ['i.indisvalid','=',true],['i.indisready','=',true],['i.indislive','=',true],['i.indisunique','=',true],
 ['i.indisexclusion','=',false],['i.indnkeyatts','=',2],['i.indnatts','=',2],
 ['i.indkey::text','=','1 2'],['i.indexprs','IS NULL'],['i.indpred','IS NULL']
];
const literal=v=>typeof v==='string'?"'"+v.replaceAll("'","''")+"'":String(v);
const compileRules=rules=>rules.map(([field,op,value])=>op==='IS NULL'?`${field} IS NULL`:
 `${field} ${op} ${value&&typeof value==='object'?value.field:literal(value)}`).join('\n AND ');
const TOAST_INTERNAL_LINK=`EXISTS(SELECT 1 FROM pg_catalog.pg_depend storage_dep
 WHERE storage_dep.classid='pg_class'::regclass AND storage_dep.objid=toast.oid AND storage_dep.objsubid=0
 AND storage_dep.refclassid='pg_class'::regclass AND storage_dep.refobjid=parent.oid AND storage_dep.refobjsubid=0
 AND storage_dep.deptype='i')`;
function fieldValue(row,path){
 const [alias,name]=path.replace('::text','').split('.');return row?.[alias]?.[name];
}
function matchesRules(row,rules){
 return rules.every(([field,op,value])=>{
  const left=fieldValue(row,field);
  if(op==='IS NULL')return left===null;
  const right=value&&typeof value==='object'?fieldValue(row,value.field):value;
  if(left===null||left===undefined||right===null||right===undefined)return false;
  return op==='='?left===right:left!==right;
 });
}
// Pure counterpart to the SQL predicates, for catalog-fixture tests. Root-table
// membership is enforced by the SQL JOIN roots; pass those same OIDs here.
export function isValidatedToastAttachment(row,rootOids,{index=false}={}){
 if(!Array.isArray(rootOids)||!rootOids.includes(row?.parent?.oid)||!matchesRules(row,TOAST_RULES))return false;
 const internal=Array.isArray(row.dependencies)&&row.dependencies.some(d=>d.classid==='pg_class'&&d.objid===row.toast.oid&&d.objsubid===0&&
  d.refclassid==='pg_class'&&d.refobjid===row.parent.oid&&d.refobjsubid===0&&d.deptype==='i');
 return internal&&(!index||matchesRules(row,TOAST_INDEX_RULES));
}

// Catalog evidence only: never probe DDL or use SET ROLE. Direct ownership is a
// deliberately conservative prerequisite, not a claim that inherited ownership
// can never authorize ALTER in PostgreSQL.
export const DDL_PERMISSION_SQL=Object.freeze({
 context:`SELECT /* qa-ddl:context */ r.oid::text AS actor_oid,
 current_database()=$1 AND current_user=$2 AND session_user=current_user AS identity_ok,
 has_database_privilege(current_user,current_database(),'CONNECT') AS database_connect,
 has_database_privilege(current_user,current_database(),'CREATE') AS database_create,
 has_schema_privilege(current_user,'public','USAGE') AS public_usage,
 has_schema_privilege(current_user,'public','CREATE') AS public_create,
 to_regnamespace('wallet_prototype_v1') IS NULL AS archive_absent
 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`,
 objects:`WITH tables AS (SELECT c.* FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN('star_wallets','star_transactions')),
 relations AS (SELECT oid,'table'::text AS kind FROM tables
 UNION SELECT indexrelid,'index' FROM pg_catalog.pg_index WHERE indrelid IN(SELECT oid FROM tables)
 UNION SELECT d.objid,'sequence' FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_class c ON c.oid=d.objid
 WHERE d.classid='pg_class'::regclass AND d.refclassid='pg_class'::regclass AND c.relkind='S'
 AND d.refobjid IN(SELECT oid FROM tables) AND d.deptype IN('a','i'))
 SELECT /* qa-ddl:objects */ x.kind,c.oid::text,c.relowner::text AS owner_oid,n.nspname AS schema,
 pg_get_userbyid(c.relowner) AS owner_name,
 CASE WHEN x.kind='table' THEN has_table_privilege(current_user,c.oid,'SELECT') ELSE true END AS readable
 FROM relations x JOIN pg_catalog.pg_class c ON c.oid=x.oid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 UNION ALL SELECT 'function',p.oid::text,p.proowner::text,n.nspname,pg_get_userbyid(p.proowner),true
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='public' AND p.proname='process_star_transaction'
 UNION ALL SELECT 'rowtype',t.oid::text,t.typowner::text,n.nspname,pg_get_userbyid(t.typowner),true
 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
 WHERE t.oid IN(SELECT reltype FROM tables)
 UNION ALL SELECT 'arraytype',t.oid::text,t.typowner::text,n.nspname,pg_get_userbyid(t.typowner),true
 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
 WHERE t.oid IN(SELECT typarray FROM pg_catalog.pg_type WHERE oid IN(SELECT reltype FROM tables))`,
 prerequisites:`SELECT /* qa-ddl:prerequisites */
 has_schema_privilege(current_user,'pg_catalog','USAGE') AS catalog_usage,
 (CASE WHEN current_setting('default_tablespace')='' THEN true ELSE has_tablespace_privilege(current_user,current_setting('default_tablespace'),'CREATE') END) AS tablespace_ok,
 (SELECT count(*)=2 AND bool_and(l.lanpltrusted AND has_language_privilege(current_user,l.oid,'USAGE'))
 FROM pg_catalog.pg_language l WHERE l.lanname IN('sql','plpgsql')) AS languages_ok,
 (SELECT count(*)=12 AND bool_and(has_type_privilege(current_user,t.oid,'USAGE'))
 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
 WHERE n.nspname='pg_catalog' AND t.typname IN('text','uuid','int4','int8','bool','void','record','trigger','timestamptz','jsonb','varchar','bpchar')) AS types_ok,
 has_function_privilege(current_user,'pg_catalog.pg_advisory_xact_lock(bigint)','EXECUTE')
 AND has_function_privilege(current_user,'pg_catalog.hashtextextended(text,bigint)','EXECUTE') AS runner_functions_ok,
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_event_trigger WHERE evtenabled<>'D') AS event_triggers_clear,
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl d WHERE d.defaclrole=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
 AND (d.defaclobjtype<>'f' OR d.defaclnamespace<>0
 OR NOT EXISTS(SELECT 1 FROM aclexplode(d.defaclacl) a WHERE a.grantee=d.defaclrole AND a.privilege_type='EXECUTE')
 OR EXISTS(SELECT 1 FROM aclexplode(d.defaclacl) a WHERE a.grantor<>d.defaclrole OR a.grantee NOT IN(0,d.defaclrole) OR a.privilege_type<>'EXECUTE' OR a.is_grantable))) AS defaults_ok`,
 dependencies:`WITH roots AS (
 SELECT 'pg_class'::regclass::oid AS classid,c.oid AS objid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN('star_wallets','star_transactions')
 UNION ALL SELECT 'pg_proc'::regclass::oid,p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='public' AND p.proname='process_star_transaction'),
 validated_toast AS (
 SELECT parent.oid AS parent_oid,toast.oid AS toast_oid FROM roots root
 JOIN pg_catalog.pg_class parent ON root.classid='pg_class'::regclass AND parent.oid=root.objid
 JOIN pg_catalog.pg_class toast ON toast.oid=parent.reltoastrelid
 JOIN pg_catalog.pg_namespace toast_ns ON toast_ns.oid=toast.relnamespace
 WHERE ${compileRules(TOAST_RULES)} AND ${TOAST_INTERNAL_LINK}),
 validated_toast_indexes AS (
 SELECT linked.parent_oid,linked.toast_oid,idx.oid AS index_oid FROM validated_toast linked
 JOIN pg_catalog.pg_class parent ON parent.oid=linked.parent_oid
 JOIN pg_catalog.pg_class toast ON toast.oid=linked.toast_oid
 JOIN pg_catalog.pg_index i ON i.indrelid=toast.oid
 JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
 JOIN pg_catalog.pg_namespace idx_ns ON idx_ns.oid=idx.relnamespace
 WHERE ${compileRules(TOAST_INDEX_RULES)}),
 attached AS (
 SELECT * FROM roots
 UNION SELECT 'pg_class'::regclass::oid,toast_oid FROM validated_toast
 UNION SELECT 'pg_class'::regclass::oid,index_oid FROM validated_toast_indexes
 UNION SELECT 'pg_class'::regclass::oid,i.indexrelid FROM pg_catalog.pg_index i WHERE i.indrelid IN(SELECT objid FROM roots WHERE classid='pg_class'::regclass)
 UNION SELECT 'pg_class'::regclass::oid,d.objid FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_class c ON c.oid=d.objid AND c.relkind='S'
 WHERE d.classid='pg_class'::regclass AND d.refclassid='pg_class'::regclass AND d.deptype IN('a','i') AND d.refobjid IN(SELECT objid FROM roots WHERE classid='pg_class'::regclass)
 UNION SELECT 'pg_constraint'::regclass::oid,k.oid FROM pg_catalog.pg_constraint k WHERE k.conrelid IN(SELECT objid FROM roots WHERE classid='pg_class'::regclass)
 UNION SELECT 'pg_attrdef'::regclass::oid,a.oid FROM pg_catalog.pg_attrdef a WHERE a.adrelid IN(SELECT objid FROM roots WHERE classid='pg_class'::regclass)
 UNION SELECT 'pg_trigger'::regclass::oid,t.oid FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN(SELECT objid FROM roots WHERE classid='pg_class'::regclass)
 UNION SELECT 'pg_type'::regclass::oid,t.oid FROM pg_catalog.pg_type t WHERE t.typrelid IN(SELECT objid FROM roots WHERE classid='pg_class'::regclass)
 UNION SELECT 'pg_type'::regclass::oid,t.typarray FROM pg_catalog.pg_type t WHERE t.typrelid IN(SELECT objid FROM roots WHERE classid='pg_class'::regclass)),
 edges AS (SELECT d.* FROM pg_catalog.pg_depend d WHERE EXISTS(SELECT 1 FROM attached a WHERE
 (a.classid=d.classid AND a.objid=d.objid) OR (a.classid=d.refclassid AND a.objid=d.refobjid)))
 SELECT /* qa-ddl:dependencies */
 NOT EXISTS(SELECT 1 FROM edges d WHERE d.deptype NOT IN('n','a','i')) AS extension_clear,
 NOT EXISTS(SELECT 1 FROM edges d WHERE NOT EXISTS(SELECT 1 FROM attached a WHERE a.classid=d.classid AND a.objid=d.objid))
 AND NOT EXISTS(SELECT 1 FROM roots root JOIN pg_catalog.pg_class parent ON root.classid='pg_class'::regclass AND parent.oid=root.objid
 WHERE parent.reltoastrelid<>0 AND NOT EXISTS(SELECT 1 FROM validated_toast t WHERE t.parent_oid=parent.oid))
 AND NOT EXISTS(SELECT 1 FROM validated_toast t WHERE (SELECT count(*) FROM pg_catalog.pg_index i WHERE i.indrelid=t.toast_oid)<>1)
 AND NOT EXISTS(SELECT 1 FROM validated_toast t JOIN pg_catalog.pg_index i ON i.indrelid=t.toast_oid
 WHERE NOT EXISTS(SELECT 1 FROM validated_toast_indexes valid WHERE valid.toast_oid=t.toast_oid AND valid.index_oid=i.indexrelid)) AS incoming_clear,
 NOT EXISTS(SELECT 1 FROM edges d WHERE NOT EXISTS(SELECT 1 FROM attached a WHERE a.classid=d.refclassid AND a.objid=d.refobjid)
 AND NOT (d.refclassid='pg_namespace'::regclass AND d.refobjid='public'::regnamespace)
 AND NOT (d.refclassid='pg_language'::regclass AND d.refobjid IN(SELECT oid FROM pg_catalog.pg_language WHERE lanname IN('sql','plpgsql')))

 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace WHERE d.refclassid='pg_type'::regclass AND t.oid=d.refobjid AND n.nspname='pg_catalog')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE d.refclassid='pg_proc'::regclass AND p.oid=d.refobjid AND n.nspname='pg_catalog')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_collation c JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace WHERE d.refclassid='pg_collation'::regclass AND c.oid=d.refobjid AND n.nspname='pg_catalog')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_opclass c JOIN pg_catalog.pg_namespace n ON n.oid=c.opcnamespace WHERE d.refclassid='pg_opclass'::regclass AND c.oid=d.refobjid AND n.nspname='pg_catalog')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_operator c JOIN pg_catalog.pg_namespace n ON n.oid=c.oprnamespace WHERE d.refclassid='pg_operator'::regclass AND c.oid=d.refobjid AND n.nspname='pg_catalog')) AS outgoing_clear,
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid IN(SELECT objid FROM roots WHERE classid='pg_class'::regclass)) AS policies_clear`
});

function requireFlags(row,keys,code){
 if(!row||!keys.every(k=>row[k]===true))qaFail(code);
}
export function validateDdlEvidence(e,snapshot){
 requireFlags(e.context,['identity_ok','database_connect','database_create','public_usage','public_create','archive_absent'],'QA_DDL_PRIVILEGES_MISSING');
 const owner=e.context.actor_oid;
 if(typeof owner!=='string'||!/^\d+$/u.test(owner))qaFail('QA_DDL_OWNER_UNCONFIRMED');
 const objects=e.objects;
 if(!Array.isArray(objects)||objects.some(o=>o.owner_oid!==owner||o.schema!=='public'||o.readable!==true||typeof o.owner_name!=='string'||!o.owner_name))qaFail('QA_DDL_OWNER_MISMATCH');
 for(const [kind,items] of [['table',snapshot.relations],['function',snapshot.functions],['index',snapshot.indexes],['sequence',snapshot.sequences]]){
  const found=objects.filter(o=>o.kind===kind).map(o=>o.oid).sort();
  if(JSON.stringify(found)!==JSON.stringify(items.map(o=>o.oid).sort())||items.some(o=>o.owner_oid!==undefined&&o.owner_oid!==owner))qaFail('QA_DDL_OBJECT_SET_MISMATCH');
 }
 if(objects.some(o=>!['table','function','index','sequence','rowtype','arraytype'].includes(o.kind))||
 ['rowtype','arraytype'].some(k=>objects.filter(o=>o.kind===k).length!==2)||new Set(objects.map(o=>`${o.kind}:${o.oid}`)).size!==objects.length)qaFail('QA_DDL_OBJECT_SET_MISMATCH');
 requireFlags(e.prerequisites,['catalog_usage','tablespace_ok','languages_ok','types_ok','runner_functions_ok','event_triggers_clear','defaults_ok'],'QA_DDL_PREREQUISITES_UNCONFIRMED');
 if(!snapshot.unsupported||!['external_fk','inheritance','dependent_view','extension_owned'].every(k=>snapshot.unsupported[k]===false))qaFail('QA_DDL_DEPENDENCY_MISMATCH');
 requireFlags(e.dependencies,['extension_clear','incoming_clear','outgoing_clear','policies_clear'],'QA_DDL_DEPENDENCY_MISMATCH');
 return {status:'catalog-checks-passed',directOwnedObjectCount:objects.length,databaseCreate:true,publicCreate:true,
  scope:'read-only-catalog-evidence',actualDdlExecuted:false,managedServiceDdlVerified:false};
}
export async function assertQaDdlPermissions(db,pins,snapshot){
 const context=(await db.query(DDL_PERMISSION_SQL.context,[pins.database,pins.migrationRole])).rows;
 const objects=(await db.query(DDL_PERMISSION_SQL.objects)).rows;
 const prerequisites=(await db.query(DDL_PERMISSION_SQL.prerequisites)).rows;
 const dependencies=(await db.query(DDL_PERMISSION_SQL.dependencies)).rows;
 if(context.length!==1||prerequisites.length!==1||dependencies.length!==1)qaFail('QA_DDL_EVIDENCE_INCOMPLETE');
 return validateDdlEvidence({context:context[0],objects,prerequisites:prerequisites[0],dependencies:dependencies[0]},snapshot);
}
