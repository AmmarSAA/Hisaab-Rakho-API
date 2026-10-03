// Never commit the generated file: it contains private records and password hashes.
import {readFile,writeFile} from 'node:fs/promises';
import {hashPassword} from '../worker/index.mjs';
const source=JSON.parse(await readFile(process.argv[2]||'database.json','utf8'));
const schema=await readFile(new URL('../migrations/0001_private.sql',import.meta.url),'utf8');
const batch=[{sql:schema}];
const ids=new Set();const emails=new Set();
for(const record of source.users){
 const {password,...profile}=record;const id=String(record.id),email=String(record.email).trim().toLowerCase();
 if(ids.has(id)||emails.has(email)||typeof password!=='string')throw new Error('User validation failed');ids.add(id);emails.add(email);
 // Historical passwords were committed publicly. Imported accounts must stay
 // locked until the owner receives a verified password reset. Do not re-enable
 // those compromised credentials by merely hashing them.
 batch.push({sql:'INSERT INTO users(id,email,password_hash,profile) VALUES(?,?,?,?)',params:[id,email,'locked:'+await hashPassword(crypto.randomUUID()+crypto.randomUUID()),JSON.stringify(profile)]});
}
for(const record of source.transaction){
 const id=String(record.id),owner=String(record.user_id);if(!ids.has(owner))throw new Error('Transaction owner missing');
 batch.push({sql:'INSERT INTO transactions(id,user_id,data) VALUES(?,?,?)',params:[id,owner,JSON.stringify({...record,id,user_id:owner})]});
}
await writeFile(process.argv[3]||'.private-migration.json',JSON.stringify({batch}));
console.log(JSON.stringify({users:ids.size,transactions:source.transaction.length,plaintextPasswordsIncluded:false,importedAccountsLocked:true}));
