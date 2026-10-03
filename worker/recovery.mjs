const message='If this email is registered, a password reset link will be sent.';
async function limited(db,key,maximum) {
  const window=Math.floor(Date.now()/900000);
  await db.prepare('INSERT INTO recovery_attempts(key,window,attempts) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN window=excluded.window THEN attempts+1 ELSE 1 END,window=excluded.window').bind(key,window).run();
  return (await db.prepare('SELECT attempts FROM recovery_attempts WHERE key=?').bind(key).first()).attempts>maximum;
}
export async function recover(request,env,input,{digest,random}) {
  const response=()=>Response.json({message},{status:202});
  const email=typeof input.email==='string'?input.email.trim().toLowerCase():'';
  const ip=await digest(request.headers.get('CF-Connecting-IP')||'local');
  const ipLimited=await limited(env.DB,'ip:'+ip,10);
  const emailLimited=await limited(env.DB,'email:'+await digest(email),3);
  if(ipLimited||emailLimited||email.length>254||!/^\S+@\S+\.\S+$/.test(email))return response();
  const job=async()=>{
  const user=await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
  if(!user||typeof env.sendRecovery!=='function')return response();
  const token=random(),tokenHash=await digest(token),now=Date.now();
  await env.DB.batch([env.DB.prepare('DELETE FROM recovery_tokens WHERE user_id=? OR expires<?').bind(user.id,now),env.DB.prepare('INSERT INTO recovery_tokens(token_hash,user_id,expires) VALUES(?,?,?)').bind(tokenHash,user.id,now+1800000)]);
  try {
    const resetUrl=new URL('/reset',env.PUBLIC_BASE_URL);resetUrl.hash=token;
    await env.sendRecovery({email,resetUrl:resetUrl.toString()});
  } catch {
    await env.DB.prepare('DELETE FROM recovery_tokens WHERE token_hash=?').bind(tokenHash).run();
  }
  };
  if(typeof env.waitUntil==='function')env.waitUntil(job().catch(()=>{}));else await job();
  return response();
}
export async function reset(env,input,{digest,hashPassword,fail}) {
  if(typeof input.token!=='string'||!/^[a-f0-9]{64}$/.test(input.token))fail(400,'Invalid or expired reset link');
  if(typeof input.password!=='string'||input.password.length<12||input.password.length>256)fail(400,'Password must contain 12 to 256 characters');
  const tokenHash=await digest(input.token),now=Date.now(),passwordHash=await hashPassword(input.password);
  const valid='SELECT user_id FROM recovery_tokens WHERE token_hash=? AND expires>?';
  const results=await env.DB.batch([
    env.DB.prepare(`UPDATE users SET password_hash=? WHERE id IN (${valid})`).bind(passwordHash,tokenHash,now),
    env.DB.prepare(`DELETE FROM sessions WHERE user_id IN (${valid})`).bind(tokenHash,now),
    env.DB.prepare(`DELETE FROM recovery_tokens WHERE user_id IN (${valid})`).bind(tokenHash,now)
  ]);
  if(Number(results[0].meta.changes)!==1)fail(400,'Invalid or expired reset link');
  return {message:'Password reset. Sign in with your new password.'};
}
export function resetPage(random) {
  const nonce=random();
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reset Hisaab password</title><body><main><h1>Reset your Hisaab password</h1><form id="reset"><label>New password (12–256 characters)<input id="password" type="password" autocomplete="new-password" minlength="12" maxlength="256" required></label><p><label>Confirm password<input id="confirm" type="password" autocomplete="new-password" minlength="12" maxlength="256" required></label></p><button>Reset password</button></form><p id="status" role="status"></p></main><script nonce="${nonce}">const token=location.hash.slice(1);history.replaceState(null,'',location.pathname);const form=document.getElementById('reset'),status=document.getElementById('status');if(!/^[a-f0-9]{64}$/.test(token)){form.hidden=true;status.textContent='Invalid reset link. Request a new link from the Hisaab app.';}form.addEventListener('submit',async event=>{event.preventDefault();const password=document.getElementById('password').value;if(password!==document.getElementById('confirm').value){status.textContent='Passwords do not match.';return;}const button=form.querySelector('button');button.disabled=true;try{const response=await fetch('/auth/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,password})});const result=await response.json();status.textContent=result.message||result.error;if(response.ok){form.reset();form.hidden=true;}}catch{status.textContent='Unable to reset password. Please try again.';}finally{button.disabled=false;}});</script></body></html>`,{headers:{'Content-Type':'text/html; charset=utf-8','Referrer-Policy':'no-referrer','Content-Security-Policy':`default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'`}});
}
