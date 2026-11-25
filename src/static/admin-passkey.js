(() => {
 const f=document.getElementById('admin-passkey-form');if(!f)return;
 const status=document.getElementById('admin-passkey-status'),button=f.querySelector('button');
 const dec=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(s.length/4)*4,'=')),c=>c.charCodeAt(0));
 const enc=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
 function opts(o){o.challenge=dec(o.challenge);if(o.user)o.user.id=dec(o.user.id);for(const k of ['allowCredentials','excludeCredentials'])if(o[k])o[k]=o[k].map(x=>({...x,id:dec(x.id)}));return o;}
 function pack(c){if(!c)throw Error('设备未返回凭据');const r=c.response,response={clientDataJSON:enc(r.clientDataJSON)};for(const k of ['attestationObject','authenticatorData','signature','userHandle'])if(r[k])response[k]=enc(r[k]);return {id:c.id,rawId:enc(c.rawId),type:c.type,response,clientExtensionResults:c.getClientExtensionResults()};}
 async function call(step,data){const r=await fetch('/auth/passkey/'+step,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const j=await r.json();if(!r.ok)throw Error(j.detail||'验证失败');return j;}
 f.addEventListener('submit',async e=>{e.preventDefault();if(!window.PublicKeyCredential||!window.isSecureContext){status.textContent='需要支持 Passkey 的 HTTPS 浏览器';return;}button.disabled=true;
 try{const data=Object.fromEntries(new FormData(f));const start=await call('start',data);status.textContent='请完成设备安全验证';const c=start.stage==='register'?await navigator.credentials.create({publicKey:opts(start.options)}):await navigator.credentials.get({publicKey:opts(start.options)});const done=await call('finish',{csrf:data.csrf,credential:pack(c)});location.assign(done.next);}
 catch(e){status.textContent='未完成验证：'+(e.name==='NotAllowedError'?'已取消或超时':e.message);}
 finally{button.disabled=false;}
 });
})();
