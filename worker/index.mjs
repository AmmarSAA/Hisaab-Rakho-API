import {recover,reset,resetPage} from './recovery.mjs';
import {relayConfigured,sendRecoveryRelay} from './mail-relay.mjs';
const encoder = new TextEncoder();
const iterations = 100000;
const hex = bytes => Array.from(new Uint8Array(bytes), x => x.toString(16).padStart(2, '0')).join('');
const unhex = value => Uint8Array.from(value.match(/../g), x => parseInt(x, 16));
const random = () => hex(crypto.getRandomValues(new Uint8Array(32)));
export async function digest(value) { return hex(await crypto.subtle.digest('SHA-256', encoder.encode(value))); }
export async function hashPassword(password, salt = random()) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = hex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:unhex(salt),iterations}, key, 256));
  return `pbkdf2:${iterations}:${salt}:${hash}`;
}
async function verifyPassword(password, stored) {
  const parts = stored?.split(':');
  if (parts?.length !== 4 || parts[0] !== 'pbkdf2' || Number(parts[1]) !== iterations) return false;
  const candidate = (await hashPassword(password, parts[2])).split(':')[3];
  let mismatch = candidate.length ^ parts[3].length;
  for (let i=0;i<candidate.length;i++) mismatch |= candidate.charCodeAt(i) ^ (parts[3].charCodeAt(i) || 0);
  return mismatch === 0;
}
class HttpError extends Error { constructor(status,message) {super(message);this.status=status;} }
const fail = (status,message) => { throw new HttpError(status,message); };
async function body(request) {
  if (!request.headers.get('Content-Type')?.startsWith('application/json')) fail(415,'JSON required');
  if (Number(request.headers.get('Content-Length') || 0)>16384) fail(413,'Request too large');
  const reader=request.body?.getReader(); if (!reader) fail(400,'JSON required');
  let size=0; const chunks=[];
  while(true) { const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>16384){await reader.cancel();fail(413,'Request too large');}chunks.push(value); }
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  let parsed;try{parsed=JSON.parse(new TextDecoder().decode(bytes));}catch{fail(400,'Invalid JSON');}
  if (!parsed || typeof parsed!=='object' || Array.isArray(parsed)) fail(400,'Object required');
  return parsed;
}
const profileFields=['name','avatar','currency_symbol','currency_name','gender'];
function cleanProfile(input) {
  const profile={};for(const field of profileFields) if (input[field] !== undefined) {if(typeof input[field]!=='string'||input[field].length>1000)fail(400,`Invalid ${field}`);profile[field]=input[field];}
  return profile;
}
function cleanTransaction(input, user, previous={}) {
  if(input.user_id!==undefined && String(input.user_id)!==user.id)fail(403,'Owner mismatch');
  const record={...previous,user_id:user.id};
  for(const key of ['name','avatar','category','description'])if(input[key]!==undefined){if(typeof input[key]!=='string'||input[key].length>2000)fail(400,`Invalid ${key}`);record[key]=input[key];}
  if(input.amount!==undefined){
    const amount=typeof input.amount==='string'&&input.amount.length<=32&&/^\d+(?:\.\d+)?$/.test(input.amount)?Number(input.amount):input.amount;
    if(typeof amount!=='number'||!Number.isFinite(amount)||amount<0||amount>1e12)fail(400,'Invalid amount');record.amount=amount;
  }
  if(input.income!==undefined){if(typeof input.income!=='boolean')fail(400,'Invalid income');record.income=input.income;}
  if(record.amount===undefined || record.income===undefined)fail(400,'Amount and income required');
  record.createdAt=previous.createdAt || new Date().toISOString();
  return record;
}
async function publicUser(db,user) {
  const sums=await db.prepare("SELECT COALESCE(SUM(CASE WHEN json_extract(data,'$.income')=1 THEN json_extract(data,'$.amount') ELSE 0 END),0) AS income,COALESCE(SUM(CASE WHEN json_extract(data,'$.income')=0 THEN json_extract(data,'$.amount') ELSE 0 END),0) AS expense FROM transactions WHERE user_id=?").bind(user.id).first();
  return {...JSON.parse(user.profile),id:user.id,email:user.email,income:sums.income,expense:sums.expense,amount:sums.income-sums.expense};
}
async function throttle(request,db) {
  const key=await digest(request.headers.get('CF-Connecting-IP') || 'local');const window=Math.floor(Date.now()/900000);
  await db.prepare('INSERT INTO auth_attempts(key,window,attempts) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN window=excluded.window THEN attempts+1 ELSE 1 END,window=excluded.window').bind(key,window).run();
  const count=await db.prepare('SELECT attempts FROM auth_attempts WHERE key=?').bind(key).first();
  if(count.attempts>20)fail(429,'Too many authentication attempts; retry later');
}
async function handler(request,env) {
  const db=env.DB,url=new URL(request.url),route=url.pathname.replace(/\/$/,'')||'/',method=request.method;
  if(route==='/'&&method==='GET')return {service:'Hisaab Rakho private API',authentication:'POST /auth/login, then Authorization: Bearer <token>',health:'/health'};
  if(route==='/health'&&method==='GET'){await db.prepare('SELECT 1').first();return {status:'ok'};}
  if(route==='/reset'&&method==='GET')return resetPage(random);
  if(route==='/auth/recover'&&method==='POST'){if(!env.sendRecovery)fail(503,'Password recovery is temporarily unavailable');return recover(request,env,await body(request),{digest,random});}
  if(route==='/auth/reset'&&method==='POST'){await throttle(request,db);return reset(env,await body(request),{digest,hashPassword,fail});}
  if((route==='/auth/login'||route==='/auth/register')&&method==='POST'){
    await throttle(request,db);const input=await body(request);
    if(typeof input.email!=='string'||input.email.length>254||!/^\S+@\S+\.\S+$/.test(input.email)||typeof input.password!=='string'||input.password.length>256)fail(400,'Invalid credentials');
    const email=input.email.trim().toLowerCase();let user;
    if(route==='/auth/register'){
      if(input.password.length<12)fail(400,'Password must contain at least 12 characters');
      user={id:crypto.randomUUID(),email,password_hash:await hashPassword(input.password),profile:JSON.stringify({...cleanProfile(input),createdAt:new Date().toISOString()})};
      try{await db.prepare('INSERT INTO users(id,email,password_hash,profile) VALUES(?,?,?,?)').bind(user.id,email,user.password_hash,user.profile).run();}catch{fail(409,'Registration unavailable for this email');}
    }else{
      user=await db.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
      const dummy='pbkdf2:100000:0000000000000000000000000000000000000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000';
      const valid=await verifyPassword(input.password,user?.password_hash||dummy);if(!user||!valid)fail(401,'Invalid credentials');
    }
    const token=random(),expires=Date.now()+3600000;
    await db.batch([db.prepare('DELETE FROM sessions WHERE expires<?').bind(Date.now()),db.prepare('INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)').bind(await digest(token),user.id,expires)]);
    return {token,expires_at:expires,user:await publicUser(db,user)};
  }
  const authorization=request.headers.get('Authorization')||'';
  if(!/^Bearer [a-f0-9]{64}$/.test(authorization))fail(401,'Authentication required');
  const tokenHash=await digest(authorization.slice(7));
  const user=await db.prepare('SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires>?').bind(tokenHash,Date.now()).first();
  if(!user)fail(401,'Session expired or invalid');
  if(route==='/auth/logout'&&method==='POST'){await db.prepare('DELETE FROM sessions WHERE token_hash=?').bind(tokenHash).run();return {success:true};}
  if(route==='/auth/me'&&method==='GET')return publicUser(db,user);
  if(route==='/db'||route==='/__rules')fail(403,'Database export disabled');
  if(route==='/users'||route==='/user'||route.startsWith('/users/')){
    const id=route.startsWith('/users/')?decodeURIComponent(route.slice(7)):null;
    if(id&&id!==user.id)fail(404,'Not found');
    if(method==='GET'){
      if([...url.searchParams.keys()].some(k=>!['id','email'].includes(k)))fail(400,'Unsupported filter');
      if((url.searchParams.has('id')&&url.searchParams.get('id')!==user.id)||(url.searchParams.has('email')&&url.searchParams.get('email').toLowerCase()!==user.email.toLowerCase()))return [];
      const result=await publicUser(db,user);return id?result:[result];
    }
    if(id&&['PATCH','PUT'].includes(method)){
      const input=await body(request);if(Object.keys(input).some(k=>!profileFields.includes(k)))fail(400,'Only profile fields may be changed');
      user.profile=JSON.stringify({...JSON.parse(user.profile),...cleanProfile(input)});
      await db.prepare('UPDATE users SET profile=? WHERE id=?').bind(user.profile,user.id).run();return publicUser(db,user);
    }
    fail(405,'Method not allowed');
  }
  if(route==='/transaction'||route.startsWith('/transaction/')){
    const id=route.startsWith('/transaction/')?decodeURIComponent(route.slice(13)):null;
    if(method==='GET'){
      if([...url.searchParams.keys()].some(k=>!['id','user_id'].includes(k)))fail(400,'Unsupported filter');
      if(url.searchParams.has('user_id')&&url.searchParams.get('user_id')!==user.id)return [];
      if(id){const row=await db.prepare('SELECT data FROM transactions WHERE id=? AND user_id=?').bind(id,user.id).first();if(!row)fail(404,'Not found');return JSON.parse(row.data);}
      const filter=url.searchParams.get('id');const result=await db.prepare(filter?'SELECT data FROM transactions WHERE user_id=? AND id=? ORDER BY id LIMIT 1000':'SELECT data FROM transactions WHERE user_id=? ORDER BY id LIMIT 1000').bind(...(filter?[user.id,filter]:[user.id])).all();return result.results.map(x=>JSON.parse(x.data));
    }
    if(method==='POST'&&!id){const input=await body(request);const record={...cleanTransaction(input,user),id:crypto.randomUUID()};await db.prepare('INSERT INTO transactions(id,user_id,data) VALUES(?,?,?)').bind(record.id,user.id,JSON.stringify(record)).run();return new Response(JSON.stringify(record),{status:201,headers:{'Content-Type':'application/json'}});}
    if(id&&['PUT','PATCH','DELETE'].includes(method)){
      const row=await db.prepare('SELECT data FROM transactions WHERE id=? AND user_id=?').bind(id,user.id).first();if(!row)fail(404,'Not found');
      if(method==='DELETE'){await db.prepare('DELETE FROM transactions WHERE id=? AND user_id=?').bind(id,user.id).run();return {};}
      const record={...cleanTransaction(await body(request),user,JSON.parse(row.data)),id};await db.prepare('UPDATE transactions SET data=? WHERE id=? AND user_id=?').bind(JSON.stringify(record),id,user.id).run();return record;
    }
    fail(405,'Method not allowed');
  }
  fail(404,'Not found');
}
export default {async fetch(request,env,ctx) {
  const suppliedSender=env.sendRecovery;
  env={...env,
    sendRecovery:suppliedSender || (relayConfigured(env)?(message=>sendRecoveryRelay(env,message)):undefined),
    waitUntil:ctx?.waitUntil?ctx.waitUntil.bind(ctx):env.waitUntil,
  };
  const origin=request.headers.get('Origin');const allowed=(env.ALLOWED_ORIGINS||'').split(',').filter(Boolean);
  if(env.PUBLIC_BASE_URL)allowed.push(new URL(env.PUBLIC_BASE_URL).origin);
  if(origin&&!allowed.includes(origin))return Response.json({error:'Origin not allowed'},{status:403});
  let response;
  try {if(request.method==='OPTIONS')response=new Response(null,{status:204});else{const result=await handler(request,env);response=result instanceof Response?result:Response.json(result);}}
  catch(error){response=Response.json({error:error instanceof HttpError?error.message:'Service unavailable'},{status:error instanceof HttpError?error.status:503});}
  const headers=new Headers(response.headers);headers.set('Cache-Control','no-store');headers.set('X-Content-Type-Options','nosniff');if(!headers.has('Content-Security-Policy'))headers.set('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'");
  if(origin){headers.set('Access-Control-Allow-Origin',origin);headers.set('Vary','Origin');headers.set('Access-Control-Allow-Headers','Authorization, Content-Type');headers.set('Access-Control-Allow-Methods','GET, POST, PUT, PATCH, DELETE, OPTIONS');}
  return new Response(response.body,{status:response.status,headers});
}};
