import {useState} from 'react';

const features=[
  ['01','Threat Intelligence','Correlate incidents, indicators and adversary activity in one command center.'],
  ['02','AI Investigation','LangGraph + RAG + compliance reasoning with Azure OpenAI.'],
  ['03','Incident Response','Trace evidence, MITRE ATT&CK techniques and NIST response state.'],
];

export default function Auth({onEnter}){
  const [mode,setMode]=useState('login');
  const [showPassword,setShowPassword]=useState(false);
  const [remember,setRemember]=useState(true);
  const [busy,setBusy]=useState(false);
  const [form,setForm]=useState({name:'',email:'',company:'',password:''});

  const submit=(e)=>{
    e.preventDefault();
    setBusy(true);
    setTimeout(()=>{localStorage.setItem('clockguard_auth','1'); onEnter();},350);
  };

  return <div className="authShell">
    <div className="authGridGlow"/>
    <div className="authBrandTop">
      <div className="brandAuthMark">C</div>
      <div><strong>CLOCK<span>GUARD</span></strong><small>AI-POWERED SECURITY OPERATIONS & INCIDENT RESPONSE</small></div>
    </div>

    <section className="authHero">
      <div className="authHeroCopy">
        <span className="eyebrow">SECURITY OPERATIONS PLATFORM · v2.0</span>
        <h1>Detect faster.<br/><em>Investigate smarter.</em></h1>
        <p>Unified cyber incident intelligence, AI investigation and response orchestration for modern security teams.</p>
        <div className="authFeatures">{features.map(([n,t,d])=><div className="authFeature" key={n}><b>{n}</b><div><strong>{t}</strong><span>{d}</span></div></div>)}</div>
        <div className="authStatus"><i/>All core services operational <span>•</span> Azure AI connected</div>
      </div>

      <div className="authCard">
        <div className="authCardTop"><span className="securityPill"><i/> SECURE ACCESS</span><span className="version">CLOCKGUARD // SOC</span></div>
        <div className="authTabs"><button className={mode==='login'?'active':''} onClick={()=>setMode('login')}>Sign in</button><button className={mode==='signup'?'active':''} onClick={()=>setMode('signup')}>Create account</button></div>
        <h2>{mode==='login'?'Welcome back':'Create your analyst account'}</h2>
        <p className="authSub">{mode==='login'?'Access your security command center and active investigations.':'Set up your workspace access for the ClockGuard SOC platform.'}</p>
        <form onSubmit={submit}>
          {mode==='signup'&&<>
            <label>FULL NAME<input required value={form.name} onChange={e=>setForm({...form,name:e.target.value})} placeholder="Riya Yadav"/></label>
            <label>ORGANIZATION<input required value={form.company} onChange={e=>setForm({...form,company:e.target.value})} placeholder="Organization / Security Team"/></label>
          </>}
          <label>WORK EMAIL<input required type="email" value={form.email} onChange={e=>setForm({...form,email:e.target.value})} placeholder="analyst@company.com"/></label>
          <label>PASSWORD<div className="passwordWrap"><input required minLength="6" type={showPassword?'text':'password'} value={form.password} onChange={e=>setForm({...form,password:e.target.value})} placeholder="••••••••••••"/><button type="button" onClick={()=>setShowPassword(!showPassword)}>{showPassword?'Hide':'Show'}</button></div></label>
          <div className="authRow"><label className="check"><input type="checkbox" checked={remember} onChange={e=>setRemember(e.target.checked)}/><span>Remember this device</span></label>{mode==='login'&&<button type="button" className="linkBtn">Forgot password?</button>}</div>
          <button className="authSubmit" disabled={busy}>{busy?'Authenticating…':mode==='login'?'Enter Command Center →':'Create Secure Workspace →'}</button>
        </form>
        <div className="authDivider"><span>OR CONTINUE WITH</span></div>
        <div className="ssoRow"><button type="button">Microsoft</button><button type="button">Google</button><button type="button">SSO</button></div>
        <p className="authLegal">By continuing, you agree to your organization's security policies and access controls.</p>
      </div>
    </section>

    <footer className="authFooter"><span>© 2026 ClockGuard Security Operations</span><span>Encrypted session <i/> &nbsp; • &nbsp; SOC access monitored</span></footer>
  </div>
}
