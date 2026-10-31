import {createHmac,timingSafeEqual,randomUUID} from 'node:crypto';
import {digest} from './wallet-qa-catalog.js';import {QA_PURCHASE_TARGET} from './purchase-qa-runtime.js';import {refuse} from './purchase-qa-policy.js';
const scopes=['inspect-installer','inspect-purchase','install-functions','activate-function'];
export function createPurchasePreparationApproval({scope,planDigest,approved,ttlMinutes=60},key,now=Date.now()){
 if(approved!==true||!scopes.includes(scope)||!/^[a-f0-9]{64}$/u.test(planDigest)||typeof key!=='string'||key.length<32||!Number.isInteger(ttlMinutes)||ttlMinutes<1||ttlMinutes>60)refuse('PURCHASE_PREPARATION_APPROVAL_REQUIRED');
 const body={version:1,id:randomUUID(),scope,target:QA_PURCHASE_TARGET,planDigest,issued:now,expires:now+ttlMinutes*60000};
 return{...body,signature:createHmac('sha256',key).update('LUNARI/PURCHASE/PREPARATION/V1\0'+digest(body)).digest('hex')};
}
export function assertPurchasePreparationApproval(a,{scope,planDigest},key,now=Date.now()){
 if(!a||Object.keys(a).sort().join(',')!=='expires,id,issued,planDigest,scope,signature,target,version'||a.version!==1||!scopes.includes(scope)||a.scope!==scope||a.planDigest!==planDigest||digest(a.target)!==digest(QA_PURCHASE_TARGET)||!Number.isFinite(now)||!Number.isFinite(a.issued)||!Number.isFinite(a.expires)||a.issued>now||a.expires<=now||a.expires<=a.issued||a.expires-a.issued>3600000||!/^[a-f0-9-]{36}$/u.test(a.id??'')||!/^[a-f0-9]{64}$/u.test(a.signature??'')||typeof key!=='string'||key.length<32)refuse('PURCHASE_PREPARATION_APPROVAL_INVALID');
 const{signature,...body}=a,wanted=createHmac('sha256',key).update('LUNARI/PURCHASE/PREPARATION/V1\0'+digest(body)).digest();
 if(!timingSafeEqual(wanted,Buffer.from(signature,'hex')))refuse('PURCHASE_PREPARATION_APPROVAL_TAMPERED');
}
