import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import worker,{hashPassword,digest} from '../worker/index.mjs';
function binding(sqlite){return {prepare(sql){let args=[];return {bind(...values){args=values;return this;},async first(){return sqlite.prepare(sql).get(...args)||null;},async run(){return {meta:sqlite.prepare(sql).run(...args)};}};},async batch(statements){sqlite.exec('BEGIN');try{const values=[];for(const statement of statements)values.push(await statement.run());sqlite.exec('COMMIT');return values;}catch(error){sqlite.exec('ROLLBACK');throw error;}}};}
test('recovery protects imported accounts, consumes once and revokes sessions',async()=>{
 const sqlite=new DatabaseSync(':memory:');for(const file of ['0001_private.sql','0002_recovery.sql'])sqlite.exec(readFileSync(new URL('../migrations/'+file,import.meta.url),'utf8'));
 const deliveries=[],jobs=[];const env={DB:binding(sqlite),PUBLIC_BASE_URL:'https://api.example',ALLOWED_ORIGINS:'https://api.example',sendRecovery:async mail=>deliveries.push(mail),waitUntil:job=>jobs.push(job)};
 sqlite.prepare('INSERT INTO users VALUES(?,?,?,?)').run('imported','owner@example.com','locked:'+await hashPassword('Old password 123!'),'{}');
 sqlite.prepare('INSERT INTO sessions VALUES(?,?,?)').run(await digest('a'.repeat(64)),'imported',Date.now()+3600000);
 const call=(path,data)=>worker.fetch(new Request('https://api.example'+path,{method:'POST',headers:{'Content-Type':'application/json',Origin:'https://api.example'},body:JSON.stringify(data)}),env);
 const unknown=await call('/auth/recover',{email:'missing@example.com'}),known=await call('/auth/recover',{email:'owner@example.com'});
 assert.equal(known.status,202);assert.equal(await unknown.text(),await known.text());await Promise.all(jobs);
 assert.equal(deliveries.length,1);const url=new URL(deliveries[0].resetUrl);assert.equal(url.origin,'https://api.example');assert.equal(url.search,'');const token=url.hash.slice(1);
 assert.equal(sqlite.prepare('SELECT token_hash FROM recovery_tokens').get().token_hash,await digest(token));
 assert.equal((await call('/auth/reset',{token:'b'.repeat(64),password:'New password 123!'})).status,400);
 assert.equal((await call('/auth/reset',{token,password:'short'})).status,400);
 assert.equal((await call('/auth/reset',{token,password:'New password 123!'})).status,200);
 assert.equal(sqlite.prepare('SELECT COUNT(*) AS n FROM sessions').get().n,0);assert.equal(sqlite.prepare('SELECT COUNT(*) AS n FROM recovery_tokens').get().n,0);
 assert.equal((await call('/auth/reset',{token,password:'Another password!'})).status,400);
 assert.equal((await call('/auth/login',{email:'owner@example.com',password:'New password 123!'})).status,200);
 const page=await worker.fetch(new Request('https://api.example/reset'),env);assert.equal(page.headers.get('Referrer-Policy'),'no-referrer');assert.match(page.headers.get('Content-Security-Policy'),/script-src 'nonce-/);assert.match(await page.text(),/history.replaceState/);
 sqlite.prepare('INSERT INTO recovery_tokens VALUES(?,?,?)').run(await digest('c'.repeat(64)),'imported',0);assert.equal((await call('/auth/reset',{token:'c'.repeat(64),password:'Another password!'})).status,400);
 for(let i=0;i<4;i++)assert.equal((await call('/auth/recover',{email:'owner@example.com'})).status,202);await Promise.all(jobs);assert.equal(deliveries.length,3);
 sqlite.close();
});
test('delivery failure invalidates token without disclosing account',async()=>{
 const sqlite=new DatabaseSync(':memory:');for(const file of ['0001_private.sql','0002_recovery.sql'])sqlite.exec(readFileSync(new URL('../migrations/'+file,import.meta.url),'utf8'));
 sqlite.prepare('INSERT INTO users VALUES(?,?,?,?)').run('u','owner@example.com','locked:hash','{}');const env={DB:binding(sqlite),PUBLIC_BASE_URL:'https://api.example',sendRecovery:async()=>{throw Error('SMTP secret error');}};
 const response=await worker.fetch(new Request('https://api.example/auth/recover',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'owner@example.com'})}),env);
 assert.equal(response.status,202);assert.equal(sqlite.prepare('SELECT COUNT(*) AS n FROM recovery_tokens').get().n,0);assert.doesNotMatch(await response.text(),/SMTP|secret/);sqlite.close();
});
