export function uniqueByIncident(rows=[]){
  const map=new Map();
  for(const r of rows){
    const id=r.incident_id||r.id||r.sequence_id;
    if(!id) continue;
    const cur=map.get(id);
    if(!cur){map.set(id,{...r,_events:1,_anomalyPeak:Number.isFinite(Number(r.anomaly_score))?Number(r.anomaly_score):null,_techniques:new Set(r.mitre_technique_id?[r.mitre_technique_id]:[]),_phases:new Set(r.nist_phase?[r.nist_phase]:[])});continue;}
    cur._events++;
    if(Number.isFinite(Number(r.anomaly_score))) cur._anomalyPeak=Math.max(cur._anomalyPeak??-Infinity,Number(r.anomaly_score));
    if(r.mitre_technique_id) cur._techniques.add(r.mitre_technique_id);
    if(r.nist_phase) cur._phases.add(r.nist_phase);
    const curRisk=Number(cur.risk_score)||0, nextRisk=Number(r.risk_score)||0;
    if(nextRisk>curRisk) Object.assign(cur,{...r,_events:cur._events,_anomalyPeak:cur._anomalyPeak,_techniques:cur._techniques,_phases:cur._phases});
  }
  return [...map.values()].map(x=>({...x,technique_count:x._techniques.size, nist_phases:[...x._phases], event_count:x._events, peak_anomaly:x._anomalyPeak}));
}
export function severityColor(sev=''){return {Critical:'#ff2bd6',High:'#ff7a45',Medium:'#f6c744',Low:'#22d3ee'}[sev]||'#8b95a7'}
export function clamp(n,a=0,b=100){return Math.max(a,Math.min(b,n))}
export function fmt(n){return Number(n||0).toLocaleString('en-IN')}
export function pct(n,d){return d?Math.round((n/d)*100):0}
export function deriveAnalytics(rows=[],summary={}){
  const unique=uniqueByIncident(rows);
  const types=summary.incident_types||{};
  const sev={Critical:summary.critical||0,High:summary.high||0,Medium:summary.medium||0,Low:summary.low||0};
  const tactics={}; const techniques={}; const phases={};
  rows.forEach(r=>{if(r.mitre_tactic)tactics[r.mitre_tactic]=(tactics[r.mitre_tactic]||0)+1;if(r.mitre_technique_id)techniques[r.mitre_technique_id]=(techniques[r.mitre_technique_id]||0)+1;if(r.nist_phase)phases[r.nist_phase]=(phases[r.nist_phase]||0)+1});
  const sorted=(o)=>Object.entries(o).sort((a,b)=>b[1]-a[1]);
  const dates={}; rows.forEach(r=>{if(r.timestamp){const d=new Date(r.timestamp); if(!Number.isNaN(d.getTime())){const k=d.toISOString().slice(0,10);dates[k]=(dates[k]||0)+1}}});
  return {unique,types,severity:sev,tactics:sorted(tactics),techniques:sorted(techniques),phases:sorted(phases),dates:Object.entries(dates).sort((a,b)=>a[0].localeCompare(b[0])).slice(-14)};
}
