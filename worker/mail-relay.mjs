export function relayConfigured(env) {
  try {const url=new URL(env.RECOVERY_RELAY_URL);return url.protocol==='https:' && url.pathname==='/api/recovery-mail' && typeof env.RECOVERY_RELAY_SECRET==='string' && env.RECOVERY_RELAY_SECRET.length>=32;} catch{return false;}
}
export async function sendRecoveryRelay(env,message,send=fetch) {
  if(!relayConfigured(env))throw new Error('Recovery mail is not configured');
  const body=JSON.stringify(message),timestamp=String(Date.now());
  const encoder=new TextEncoder();
  const key=await crypto.subtle.importKey('raw',encoder.encode(env.RECOVERY_RELAY_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const signature=Array.from(new Uint8Array(await crypto.subtle.sign('HMAC',key,encoder.encode(timestamp+'\n'+body))),x=>x.toString(16).padStart(2,'0')).join('');
  const response=await send(env.RECOVERY_RELAY_URL,{method:'POST',headers:{'Content-Type':'application/json','X-Hisaab-Timestamp':timestamp,'X-Hisaab-Signature':signature},body,redirect:'error',signal:AbortSignal.timeout(25000)});
  if(!response.ok)throw new Error('Recovery delivery not accepted');
}
