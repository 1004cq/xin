(() => {
 const file=document.getElementById('verify-file');if(!file)return;
 const expected=document.getElementById('expected-sha'),actual=document.getElementById('actual-sha'),status=document.getElementById('hash-result'),ots=document.getElementById('verify-ots'),node=document.getElementById('node-button'),out=document.getElementById('node-result'),report=document.getElementById('node-report');
 const m=location.hash.match(/^#sha256=([a-fA-F0-9]{64})$/);if(m)expected.value=m[1].toLowerCase();
 let hash=null,version=0;
 function reset(){version++;hash=null;actual.hidden=true;status.textContent='';out.textContent='';report.hidden=true;}
 file.addEventListener('change',reset);expected.addEventListener('input',reset);ots.addEventListener('change',()=>{out.textContent='';report.hidden=true;});
 document.getElementById('hash-button').addEventListener('click',async()=>{
  reset();const v=version;
  try{if(!crypto.subtle)throw Error('需要 HTTPS 环境');const f=file.files[0];if(!f||f.size>50*1024*1024)throw Error('请选择不超过 50 MB 的原始文件');
   const bytes=await crypto.subtle.digest('SHA-256',await f.arrayBuffer());if(v!==version)return;
   hash=Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,'0')).join('');actual.textContent=hash;actual.hidden=false;
   const target=expected.value.trim().toLowerCase();status.textContent=/^[a-f0-9]{64}$/.test(target)?(hash===target?'文件指纹一致；尚未核验主网。':'文件指纹不一致，请核对原件。'):'已计算指纹，请输入凭证中的 SHA-256。';
  }catch(e){if(v===version)status.textContent=e.message;}
 });
 if(node)node.addEventListener('click',async()=>{
  const v=version,selected=ots.files[0];if(!hash||!selected||selected.size>65536){out.textContent='请先计算原文件指纹，再选择不超过64 KB的 OTS 证明。';return;}
  if(expected.value.trim()&&hash!==expected.value.trim().toLowerCase()){out.textContent='预期指纹不一致，请核对后再验证。';return;}
  node.disabled=true;report.hidden=true;out.textContent='正在核验配置的主网节点…';
  try{const proof=btoa(Array.from(new Uint8Array(await selected.arrayBuffer()),b=>String.fromCharCode(b)).join(''));
   const r=await fetch('/verify/node',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sha256:hash,proof})});const j=await r.json();if(v!==version||selected!==ots.files[0])return;
   if(!r.ok)throw Error(typeof j.detail==='string'?j.detail:'主网未核验通过');out.textContent='本站配置节点核验通过（至少六个确认）。建议独立复核。';report.textContent='区块高度 '+j.height+'\n区块哈希 '+j.block_hash+'\n核验时间 '+j.verified_at_utc;report.hidden=false;
  }catch(e){if(v===version&&selected===ots.files[0])out.textContent=e.message;}finally{node.disabled=false;}
 });
})();
