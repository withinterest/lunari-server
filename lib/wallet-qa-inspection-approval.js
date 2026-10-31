import {createHash,createHmac,hkdfSync,timingSafeEqual,randomUUID} from 'node:crypto';
import {readFile,lstat} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {qaFail} from './wallet-qa-target.js';

export const INSPECTION_APPROVAL_FILE='.env.wallet-qa-inspection-approval.local.json';
export const MAX_INSPECTION_TTL_MS=60*60*1000;
const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const KEYS=['version','status','scope','approvalId','targetSha256','issuedAt','expiresAt','reviewReference','signature'];
function canonical(value){
 if(Array.isArray(value))return value.map(canonical);
 if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));
 return value;
}
export function inspectionTargetDigest(pins){
 return createHash('sha256').update(JSON.stringify(canonical(pins))).digest('hex');
}
function signingKey(env){
 const key=env?.NEON_API_KEY;
 if(typeof key!=='string'||!key||key!==key.trim())qaFail('QA_INSPECTION_SIGNING_KEY_MISSING');
 // No new persistent secret. API-key rotation deliberately invalidates approvals.
 // Domain-separated local authentication only; never transmit this signature.
 return hkdfSync('sha256',Buffer.from(key,'utf8'),Buffer.from('LUNARI/QA/LOCAL-APPROVAL/V1'),Buffer.from('inspect-prototype-only'),32);
}
function signature(payload,env){return createHmac('sha256',signingKey(env)).update(JSON.stringify(canonical(payload))).digest('hex');}
export function createInspectionApproval(pins,env,{reviewReference,ttlMinutes,now=Date.now()}={}){
 if(typeof reviewReference!=='string'||!reviewReference.trim()||reviewReference.length>200||/[\r\n\x00-\x1f]/u.test(reviewReference)||
 !Number.isInteger(ttlMinutes)||ttlMinutes<1||ttlMinutes>60||!Number.isFinite(now))qaFail('QA_INSPECTION_REQUEST_INVALID');
 const payload={version:1,status:'approved-read-only',scope:'qa-inspect-prototype-only',approvalId:randomUUID(),
 targetSha256:inspectionTargetDigest(pins),issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+ttlMinutes*60000).toISOString(),reviewReference};
 return {...payload,signature:signature(payload,env)};
}
export function assertInspectionApproval(approval,pins,env,now=Date.now()){
 if(!approval||typeof approval!=='object'||Array.isArray(approval))qaFail('QA_INSPECTION_APPROVAL_MISSING');
 if(Object.keys(approval).length!==KEYS.length||!KEYS.every(k=>Object.hasOwn(approval,k))||approval.version!==1||
 approval.status!=='approved-read-only'||approval.scope!=='qa-inspect-prototype-only'||
 !/^[a-f0-9-]{36}$/u.test(approval.approvalId??'')||!/^[a-f0-9]{64}$/u.test(approval.targetSha256??'')||
 !/^[a-f0-9]{64}$/u.test(approval.signature??'')||typeof approval.reviewReference!=='string'||!approval.reviewReference.trim()||
 approval.reviewReference.length>200||/[\r\n\x00-\x1f]/u.test(approval.reviewReference))qaFail('QA_INSPECTION_APPROVAL_INVALID');
 const {signature:provided,...payload}=approval;
 if(!timingSafeEqual(Buffer.from(provided,'hex'),Buffer.from(signature(payload,env),'hex')))qaFail('QA_INSPECTION_APPROVAL_TAMPERED');
 if(approval.targetSha256!==inspectionTargetDigest(pins))qaFail('QA_INSPECTION_TARGET_CHANGED');
 const issued=Date.parse(approval.issuedAt),expires=Date.parse(approval.expiresAt);
 if(!Number.isFinite(now)||!Number.isFinite(issued)||!Number.isFinite(expires)||issued>now||expires<=now||expires<=issued||
 expires-issued>MAX_INSPECTION_TTL_MS||new Date(issued).toISOString()!==approval.issuedAt||new Date(expires).toISOString()!==approval.expiresAt)
 qaFail('QA_INSPECTION_APPROVAL_EXPIRED_OR_INVALID_TIME');
}
export async function loadInspectionApproval({root=ROOT}={}){
 try{
  const path=resolve(root,INSPECTION_APPROVAL_FILE),stat=await lstat(path);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size>16384)qaFail('QA_INSPECTION_APPROVAL_INVALID');
  return JSON.parse(await readFile(path,'utf8'));
 }catch(e){if(typeof e?.code==='string'&&e.code.startsWith('QA_'))throw e;qaFail('QA_INSPECTION_APPROVAL_UNAVAILABLE');}
}
