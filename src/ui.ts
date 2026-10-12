// Audit UI: server-rendered HTML page (no build step, no framework).
// Pure presentation — no imports from other cerberus modules.

export function auditPage(): string {
	return `<!doctype html>
<html><head><meta charset="utf-8"><title>Cerberus — audit</title>
<style>body{font-family:system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%;margin-bottom:2rem}th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.85rem}
.allow{color:#0a0}.deny{color:#c00}.pend{color:#b80}
.sev{display:inline-block;padding:.1rem .45rem;border-radius:.6rem;font-size:.75rem;font-weight:600;color:#fff}
.sev-info{background:#6b7280}.sev-low{background:#0ea5e9}.sev-medium{background:#d97706}.sev-high{background:#dc2626}.sev-critical{background:#7c2d12}
.filters{margin:.5rem 0}input,select,button{font-size:.85rem;padding:.25rem .5rem;margin-right:.5rem}</style></head>
<body><h1>Cerberus — decision audit</h1>
<p id="stats">loading…</p>

<h2>Pending elevations</h2>
<div class="filters">
<input id="akey" type="password" placeholder="approver key (stored locally)" style="width:22rem">
<button onclick="saveKey()">save</button>
<span id="keystat" style="font-size:.8rem;color:#666"></span>
</div>
<table><thead><tr><th>ticket</th><th>repo</th><th>scope</th><th>ttl</th><th>justification</th><th>approvals</th><th></th></tr></thead>
<tbody id="elev"></tbody></table>

<h2>Decisions</h2>
<div class="filters">
<input id="f-agent" placeholder="filter agent…">
<select id="f-dec"><option value="">allow+deny</option><option value="allow">allow</option><option value="deny">deny</option></select>
<select id="f-sev"><option value="">any severity</option><option value="info">info</option><option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option></select>
<button onclick="load()">apply</button>
</div>
<table><thead><tr><th>time</th><th>agent</th><th>action</th><th>repo</th><th>branch</th><th>severity</th><th>decision</th><th>reason</th></tr></thead>
<tbody id="rows"></tbody></table>

<h2>Observed repo activity <span id="unexp" style="font-size:.8rem"></span></h2>
<p style="font-size:.85rem;color:#666">Artifacts events reconciled against decisions. A push with no matching allow-decision is flagged UNEXPLAINED.</p>
<table><thead><tr><th>time</th><th>event</th><th>repo</th><th>ref</th><th>verdict</th></tr></thead>
<tbody id="evts"></tbody></table>
<script>
let cache=[];
async function load(){
  const r=await fetch('/v1/decisions?limit=200').then(r=>r.json());
  document.getElementById('stats').textContent=
    \`total \${r.stats.total} · allowed \${r.stats.allowed} · denied \${r.stats.denied}\`;
  cache=r.decisions; render();
  const e=await fetch('/v1/elevations?status=pending').then(r=>r.json());
  document.getElementById('elev').innerHTML=e.elevations.map(t=>
    \`<tr><td>\${t.id}</td><td>\${t.repo}</td><td>\${t.tokenScope}</td><td>\${t.ttlSeconds}s</td><td>\${t.justification}</td>\`+
    \`<td>\${(t.approvals??[]).length}/\${t.requiredApprovals??1}</td>\`+
    \`<td><button onclick="decide('\${t.id}',true)">approve</button> <button onclick="decide('\${t.id}',false)">reject</button></td></tr>\`).join('')
    || '<tr><td colspan=7>none</td></tr>';
}
function render(){
  const a=document.getElementById('f-agent').value, d=document.getElementById('f-dec').value,
        s=document.getElementById('f-sev').value;
  document.getElementById('rows').innerHTML=cache
    .filter(x=>(!a||x.req.agentId.includes(a))&&(!d||(d==='allow')===x.decision.allowed)
      &&(!s||(x.decision.severity||'info')===s))
    .map(x=>{const sev=x.decision.severity||'info';
      return \`<tr><td>\${new Date(x.ts).toLocaleTimeString()}</td><td>\${x.req.agentId}</td><td>\${x.req.action}</td>\`+
    \`<td>\${x.req.repo}</td><td>\${x.req.branch||''}</td>\`+
    \`<td><span class="sev sev-\${sev}">\${sev}</span></td>\`+
    \`<td class="\${x.decision.allowed?'allow':'deny'}">\${x.decision.allowed?'ALLOW':'DENY'}</td>\`+
    \`<td>\${x.decision.reason}</td></tr>\`;}).join('');
}
async function decide(id,ok){
  const k=localStorage.getItem('cerberus_akey')||'';
  const r=await fetch(\`/v1/elevate/\${id}/\${ok?'approve':'reject'}\`,{method:'POST',headers:{'authorization':'Bearer '+k}});
  if(r.status===401||r.status===403){alert('approver key missing or not authorized');return;}
  load();
}
function saveKey(){
  const v=document.getElementById('akey').value.trim();
  if(v)localStorage.setItem('cerberus_akey',v);
  document.getElementById('keystat').textContent=v?'key saved in this browser':'';
}
document.getElementById('akey').value=localStorage.getItem('cerberus_akey')||'';
if(localStorage.getItem('cerberus_akey'))document.getElementById('keystat').textContent='key saved in this browser';
async function loadEvents(){
  const r=await fetch('/v1/events?limit=100').then(r=>r.json());
  document.getElementById('unexp').textContent =
    r.unexplained>0 ? \`⚠ \${r.unexplained} UNEXPLAINED\` : '· all explained';
  document.getElementById('unexp').style.color = r.unexplained>0 ? '#c00' : '#0a0';
  document.getElementById('evts').innerHTML=r.events.map(e=>{
    const v=e.verdict==='explained'?'<span class="allow">explained'+(e.explainedBy?\` (\${e.explainedBy})\`:'')+'</span>'
      :e.verdict==='unexplained'?'<span class="deny">UNEXPLAINED</span>'
      :'<span class="pend">observed</span>';
    return \`<tr><td>\${new Date(e.ts).toLocaleTimeString()}</td><td>\${e.type.replace('cf.artifacts.repo.','')}</td>\`+
      \`<td>\${e.repo}</td><td>\${(e.ref||'').replace('refs/heads/','')}</td><td>\${v}</td></tr>\`;
  }).join('') || '<tr><td colspan=5>no events yet — push something</td></tr>';
}
load();
loadEvents();
setInterval(loadEvents, 5000);
</script></body></html>`;
}
