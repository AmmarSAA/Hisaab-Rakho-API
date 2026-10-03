import nodemailer from 'nodemailer';

export function smtpOptions(env) {
  const port=Number(env.SMTP_PORT || 465);
  if(!env.SMTP_HOST || !env.SMTP_USER || !env.SMTP_PASS || ![465,587].includes(port))throw new Error('Recovery mail is not configured');
  if(/[\s/\r\n]/.test(env.SMTP_HOST))throw new Error('Invalid SMTP host');
  return {
    host:env.SMTP_HOST,port,secure:port===465,requireTLS:true,
    auth:{user:env.SMTP_USER,pass:env.SMTP_PASS},
    tls:{rejectUnauthorized:true,servername:env.SMTP_HOST},
    pool:false,logger:false,debug:false,
    connectionTimeout:10000,greetingTimeout:10000,socketTimeout:15000,
    disableFileAccess:true,disableUrlAccess:true,
  };
}
export function mailConfigured(env) {
  try {smtpOptions(env);return /^\S+@\S+\.\S+$/.test(env.MAIL_FROM||env.SMTP_USER);}catch{return false;}
}
export async function sendRecoveryEmail(env,{email,resetUrl},createTransport=nodemailer.createTransport) {
  const from=env.MAIL_FROM || env.SMTP_USER;
  if(!/^\S+@\S+\.\S+$/.test(from)||/[\r\n]/.test(email)||!/^\S+@\S+\.\S+$/.test(email))throw new Error('Invalid email configuration');
  const link=new URL(resetUrl),publicBase=new URL(env.PUBLIC_BASE_URL);
  if(link.origin!==publicBase.origin||link.protocol!=='https:'||link.pathname!=='/reset'||!/^#[a-f0-9]{64}$/.test(link.hash))throw new Error('Invalid recovery URL');
  const transporter=createTransport(smtpOptions(env));
  try {
    const result=await transporter.sendMail({
      from:{name:'Hisaab Rakho',address:from},to:email,
      subject:'Reset your Hisaab Rakho password',
      text:`A password reset was requested for your Hisaab Rakho account.\n\nOpen this single-use link within 30 minutes:\n${link.href}\n\nIf you did not request this, ignore this email. Your password has not changed.`,
      disableFileAccess:true,disableUrlAccess:true,
    });
    if(result.rejected?.length || !result.accepted?.length)throw new Error('Recovery delivery not accepted');
  } finally {transporter.close();}
}
