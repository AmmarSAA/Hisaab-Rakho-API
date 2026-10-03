import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {relayConfigured,sendRecoveryRelay} from '../worker/mail-relay.mjs';
test('mail relay signs exact body and fails closed on failed delivery',async()=>{
 const env={RECOVERY_RELAY_URL:'https://hisaab.example/api/recovery-mail',RECOVERY_RELAY_SECRET:'test-only-secret-'.repeat(4)};
 const message={email:'owner@example.com',resetUrl:'https://api.example/reset#'+'a'.repeat(64)};
 await sendRecoveryRelay(env,message,async(url,options)=>{
  assert.equal(url,env.RECOVERY_RELAY_URL);assert.equal(options.redirect,'error');
  const expected=createHmac('sha256',env.RECOVERY_RELAY_SECRET).update(options.headers['X-Hisaab-Timestamp']+'\n'+options.body).digest('hex');
  assert.equal(options.headers['X-Hisaab-Signature'],expected);assert.deepEqual(JSON.parse(options.body),message);
  return new Response(null,{status:204});
 });
 assert.equal(relayConfigured({...env,RECOVERY_RELAY_URL:'http://hisaab.example/api/recovery-mail'}),false);
 await assert.rejects(sendRecoveryRelay(env,message,async()=>new Response(null,{status:502})),/not accepted/);
});
