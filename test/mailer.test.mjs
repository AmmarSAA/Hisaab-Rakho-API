import test from 'node:test';
import assert from 'node:assert/strict';
import {smtpOptions,mailConfigured,sendRecoveryEmail} from '../worker/mailer.mjs';
import worker from '../worker/index.mjs';
const env={SMTP_HOST:'smtp.example.com',SMTP_USER:'hisaab@example.com',SMTP_PASS:'synthetic-only',MAIL_FROM:'hisaab@example.com',PUBLIC_BASE_URL:'https://api.example'};
test('Nodemailer uses authenticated TLS and closes transport',async()=>{
 let options,message,closed=false;
 await sendRecoveryEmail(env,{email:'owner@example.com',resetUrl:'https://api.example/reset#'+'a'.repeat(64)},o=>{options=o;return{async sendMail(m){message=m;return {accepted:['owner@example.com'],rejected:[]};},close(){closed=true;}};});
 assert.equal(options.secure,true);assert.equal(options.tls.rejectUnauthorized,true);assert.equal(options.requireTLS,true);assert.equal(options.logger,false);assert.equal(options.debug,false);
 assert.equal(message.to,'owner@example.com');assert.equal(message.disableFileAccess,true);assert.equal(message.disableUrlAccess,true);assert.equal(closed,true);
 assert.equal(smtpOptions({...env,SMTP_PORT:587}).secure,false);assert.equal(smtpOptions({...env,SMTP_PORT:587}).requireTLS,true);
 assert.equal(mailConfigured({...env,SMTP_PASS:''}),false);
});
test('Recovery mail cannot use attacker origin or report rejected delivery as accepted',async()=>{
 await assert.rejects(sendRecoveryEmail(env,{email:'owner@example.com',resetUrl:'https://attacker.example/reset#'+'a'.repeat(64)}),/Invalid recovery URL/);
 await assert.rejects(sendRecoveryEmail(env,{email:'owner@example.com',resetUrl:'https://api.example/reset#'+'a'.repeat(64)},()=>({async sendMail(){return{accepted:[],rejected:['owner@example.com']};},close(){}})),/not accepted/);
});
test('Reset page permits its nonce script and recovery failure retains own-origin CORS',async()=>{
 const configuration={PUBLIC_BASE_URL:'https://api.example'};
 const page=await worker.fetch(new Request('https://api.example/reset'),configuration);
 assert.equal(page.status,200);assert.match(page.headers.get('Content-Security-Policy'),/script-src 'nonce-/);
 assert.equal(page.headers.get('Referrer-Policy'),'no-referrer');
 const response=await worker.fetch(new Request('https://api.example/auth/recover',{method:'POST',headers:{Origin:'https://api.example','Content-Type':'application/json'},body:JSON.stringify({email:'owner@example.com'})}),configuration);
 assert.equal(response.status,503);assert.equal(response.headers.get('Access-Control-Allow-Origin'),'https://api.example');
});
