(() => {
 const form=document.getElementById('passkey-form'); if(!form)return;
 const status=document.getElementById('passkey-status'), button=form.querySelector('button');
 const dec=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(s.length/4)*4,'=')),c=>c.charCodeAt(0));
 const enc=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
 function options(o){o.challenge=dec(o.challenge);if(o.user)o.user.id=dec(o.user.id);for(const k of ['allowCredentials','excludeCredentials'])if(o[k])o[k]=o[k].map(x=>({...x,id:dec(x.id)}));return o;}
 function credential(c){if(!c)throw Error('设备未返回凭据');const r=c.response, response={clientDataJSON:enc(r.clientDataJSON)};for(const k of ['attestationObject','authenticatorData','signature','userHandle'])if(r[k])response[k]=enc(r[k]);return {id:c.id,rawId:enc(c.rawId),type:c.type,response,clientExtensionResults:c.getClientExtensionResults()};}
 const call=async(step,data)=>{const r=await fetch(location.pathname+'/passkey/'+step,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const j=await r.json();if(!r.ok)throw Error(typeof j.detail==='string'?j.detail:'请求失败');return j;};
 form.addEventListener('submit',async e=>{e.preventDefault();if(!window.PublicKeyCredential||!window.isSecureContext){status.textContent='需要支持 Passkey 的 HTTPS 浏览器。';return;}
 button.disabled=true;const f=Object.fromEntries(new FormData(form));
 try{status.textContent='请创建此合同专用 Passkey';const reg=await call('start',f);
 const c=await navigator.credentials.create({publicKey:options(reg)});
 status.textContent='请再次验证，以确认此合同';const auth=await call('register',{csrf:f.csrf,credential:credential(c)});
 const assertion=await navigator.credentials.get({publicKey:options(auth)});
 const done=await call('finish',{csrf:f.csrf,credential:credential(assertion)});location.assign(done.next);
 }catch(e){status.textContent='未完成确认：'+(e.name==='NotAllowedError'?'设备验证取消或超时':e.message);}
 finally{button.disabled=false;}
 });
})();
