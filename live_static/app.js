'use strict';
const $ = id => document.getElementById(id);
let token = '', pending = null, connected = false;
async function api(path, data) {
  const response = await fetch('/live/' + path, data === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json','X-AgentShield-Token':token},body:JSON.stringify(data)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed');
  return result;
}
async function action(button, status, work) {
  $(button).disabled = true; $(status).textContent = 'Working…';
  try { await work(); } catch(e) { $(status).textContent = e.message; }
  finally { $(button).disabled = false; if(button === 'review' && !connected) $(button).disabled=true; }
}
function clearReview(){pending=null; $('approval').hidden=true; $('approve').disabled=false; $('deny').disabled=false;}
async function cancelReview(){const old=pending; clearReview(); if(old) await api('approve',{approval_id:old,choice:'DENY'});}
function showInspection(report){
  $('inspection').hidden=false; $('decision').textContent=report.decision+' — '+report.reason; $('decision').dataset.status=report.decision==='ALLOW'?'PASS':'FAIL'; $('risk').textContent='Threat risk: '+report.risk+' • Request: '+report.request_id; $('checks').replaceChildren();
  for(const item of report.checks){const row=document.createElement('div');row.className='check';const status=document.createElement('strong');status.dataset.status=item.status;status.textContent=item.status;const detail=document.createElement('div');const name=document.createElement('strong');name.textContent=item.name;const desc=document.createElement('small');desc.textContent=item.detail;detail.append(name,desc);row.append(status,detail);$('checks').append(row);}
}
$('analyze').onclick=()=>action('analyze','docStatus',async()=>{
  $('inspection').hidden=true; $('useAnswer').disabled=true; $('answer').textContent=''; $('source').textContent='';
  const f=$('file').files[0]; if(!f || f.size>4*1024*1024) throw Error('Select a file of up to 4 MB.');
  $('useAnswer').disabled=true; $('answer').textContent=''; $('source').textContent='';
  const encoded=await new Promise((resolve,reject)=>{const reader=new FileReader(); reader.onload=()=>resolve(String(reader.result).split(',')[1]);reader.onerror=reject;reader.readAsDataURL(f);});
  const result=await api('analyze',{name:f.name,file:encoded,question:$('question').value});
  showInspection(result.security); $('answer').textContent=result.answer || 'No AI answer returned.'; $('source').textContent=result.text; $('docStatus').textContent=result.security.decision==='BLOCK'?'Analysis blocked — see security inspection.':!result.answer?'Authorized, but analysis failed.':result.truncated?'Analysis complete — source truncated to 12,000 characters.':'Analysis complete.'; $('useAnswer').disabled=!result.answer;
});
$('useAnswer').onclick=async()=>{try{await cancelReview();$('body').value=$('answer').textContent; $('mailStatus').textContent='Analysis copied into editable email. Nothing sent.';}catch(e){$('mailStatus').textContent=e.message;}};
$('draft').onclick=()=>action('draft','mailStatus',async()=>{await cancelReview(); const r=await api('draft',{instruction:$('instruction').value}); $('subject').value=r.subject; $('body').value=r.body; $('mailStatus').textContent='Draft ready. Review and edit before sending.';});
$('review').onclick=()=>action('review','mailStatus',async()=>{await cancelReview(); const r=await api('prepare',{recipient:$('recipient').value.trim(),subject:$('subject').value,body:$('body').value}); pending=r.approval_id; $('preview').textContent=`To: ${r.mail.recipient}\nSubject: ${r.mail.subject}\n\n${r.mail.body}`; $('approval').hidden=false; $('mailStatus').textContent='Awaiting explicit approval.';});
for(const id of ['recipient','subject','body']) $(id).addEventListener('input',()=>{if(pending)cancelReview().catch(e=>$('mailStatus').textContent=e.message);});
async function decide(choice){if(!pending)return;const id=pending;pending=null;$('approve').disabled=true;$('deny').disabled=true;$('mailStatus').textContent='Processing approval…';try{const r=await api('approve',{approval_id:id,choice});$('mailStatus').textContent=r.message+(r.message_id?' Message ID: '+r.message_id:'');}catch(e){$('mailStatus').textContent=e.message+' Check Gmail Sent before retrying.';}finally{clearReview();}}
$('approve').onclick=()=>decide('APPROVE');$('deny').onclick=()=>decide('DENY');
$('review').disabled=true;
api('state').then(r=>{token=r.token;connected=r.gmail_configured;$('state').textContent=`Local model: ${r.model} • ${connected?'Gmail token present (authorization checked at send)':'Gmail not connected — run gmail_setup.py'}`;$('review').disabled=!connected;}).catch(e=>$('state').textContent=e.message);
