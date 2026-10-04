import React,{useEffect,useState}from'react';
import{createRoot}from'react-dom/client';
import{ShieldCheck,Search,MessageSquareText,Mail,History,Activity,AlertTriangle,CheckCircle2,ChevronRight}from'lucide-react';
import'./styles.css';

const API=import.meta.env.VITE_API_BASE_URL||'http://127.0.0.1:8000';

function App(){
 const[tab,setTab]=useState('dashboard'),[url,setUrl]=useState(''),[sms,setSms]=useState(''),[result,setResult]=useState<any>(null),[loading,setLoading]=useState(false),[stats,setStats]=useState<any>({}),[history,setHistory]=useState<any[]>([]);

 async function refresh(){
  try{
   const[a,b]=await Promise.all([fetch(API+'/api/stats'),fetch(API+'/api/history')]);
   setStats(await a.json());
   setHistory(await b.json())
  }catch{}
 }

 useEffect(()=>{refresh()},[]);

 async function scan(kind:string){
  setLoading(true);
  setResult(null);

  const scanStart = Date.now();

  try{
   const body=kind==='url'?{url}:{text:sms};

   const r=await fetch(API+`/api/analyze/${kind}`,{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)
   });

   const d=await r.json();

   if(!r.ok)throw Error(d.detail||'Analysis failed');

   // Keep the professional scanning interface visible
   // long enough for the user to see the analysis stages.
   const elapsed=Date.now()-scanStart;
   const minimumScanTime=2200;

   if(elapsed<minimumScanTime){
    await new Promise(resolve=>setTimeout(
     resolve,
     minimumScanTime-elapsed
    ));
   }

   setResult(d);
   refresh();

  }catch(e:any){
   const elapsed=Date.now()-scanStart;
   const minimumScanTime=2200;

   if(elapsed<minimumScanTime){
    await new Promise(resolve=>setTimeout(
     resolve,
     minimumScanTime-elapsed
    ));
   }

   setResult({error:e.message});

  }finally{
   setLoading(false);
  }
 }

 return <div className="app">

  {loading&&<ScanLoading/>}

  <aside>
   <div className="brand">
    <div className="logo"><ShieldCheck/></div>
    <div><b>PHISHGUARD</b><span>Threat Detection</span></div>
   </div>

   {[
    ['dashboard','Dashboard',Activity],
    ['url','URL Scanner',Search],
    ['sms','SMS Scanner',MessageSquareText],
    ['email','Email Scanner',Mail],
    ['history','Scan History',History]
   ].map(([id,name,I]:any)=>
    <button className={'nav '+(tab===id?'active':'')} onClick={()=>setTab(id)} key={id}>
     <I/><span>{name}</span>
    </button>
   )}

   <div className="safe">
    DEFENSIVE MODE<br/>
    <small>Passive analysis only</small>
   </div>
  </aside>

  <main>
   <header>
    <div>
     <span className="eyebrow">SECURITY OPERATIONS</span>
     <h1>
      {tab==='dashboard'?'Threat Overview':
       tab==='url'?'URL Scanner':
       tab==='sms'?'SMS Scam Detector':
       tab==='email'?'Email Analyzer':'Scan History'}
     </h1>
    </div>
    <div className="live"><i/> Engine Online</div>
   </header>

   {tab==='dashboard'&&<Dashboard stats={stats} go={setTab}/>}

   {tab==='url'&&
    <Scanner
     title="Analyze a suspicious website"
     placeholder="https://example.com/login"
     value={url}
     setValue={setUrl}
     onScan={()=>scan('url')}
     loading={loading}
    />
   }

   {tab==='sms'&&
    <Scanner
     title="Analyze a suspicious SMS"
     placeholder="Paste the SMS message here..."
     value={sms}
     setValue={setSms}
     onScan={()=>scan('sms')}
     loading={loading}
     multi
    />
   }

   {tab==='email'&&<Email onResult={setResult} refresh={refresh}/>}
   {tab==='history'&&<HistoryView history={history}/>}
   {result&&<Result result={result} close={()=>setResult(null)}/>}
  </main>
 </div>
}

function ScanLoading(){
 return <div className="scan-overlay">
  <div className="scan-loader">
   <div className="scan-ring"></div>
   <div className="scan-ring scan-ring-two"></div>
   <div className="scan-core">
    <ShieldCheck/>
   </div>
  </div>

  <div className="scan-title">Analyzing threat...</div>

  <div className="scan-subtitle">
   Running PHISHGUARD detection pipeline
  </div>

  <div className="scan-steps">
   <div><i/>Normalizing input</div>
   <div><i/>Running regex rules</div>
   <div><i/>Analyzing URL &amp; domain signals</div>
   <div><i/>Correlating threat indicators</div>
   <div><i/>Calculating risk score</div>
  </div>
 </div>
}

function Dashboard({stats,go}:any){
 return <section>
  <div className="hero">
   <div>
    <span className="tag">REAL-TIME DEFENSIVE ANALYSIS</span>
    <h2>Detect phishing before it becomes a breach.</h2>
    <p>Executable regex rules, URL heuristics, brand protection and explainable risk scoring.</p>
   </div>
   <ShieldCheck size={90}/>
  </div>

  <div className="cards">
   <Card l="Total Scans" v={stats.total_scans||0}/>
   <Card l="Threats Detected" v={stats.threats_detected||0}/>
   <Card l="Likely Phishing" v={stats.likely_phishing||0}/>
   <Card l="Avg Risk" v={stats.average_risk||0}/>
  </div>

  <div className="grid">
   <div className="panel">
    <h3>Detection Pipeline</h3>
    {[
     'Regex / Pattern Detection',
     'URL & Domain Heuristics',
     'Brand / Typosquatting',
     'Threat Intelligence',
     'Risk Scoring'
    ].map((x,i)=>
     <div className="pipe" key={x}>
      <b>{i+1}</b>{x}<ChevronRight/>
     </div>
    )}
   </div>

   <div className="panel">
    <h3>Quick Scan</h3>
    <button className="quick" onClick={()=>go('url')}>
     <Search/> Scan URL <ChevronRight/>
    </button>
    <button className="quick" onClick={()=>go('sms')}>
     <MessageSquareText/> Analyze SMS <ChevronRight/>
    </button>
   </div>
  </div>
 </section>
}

function Card({l,v}:any){
 return <div className="card">
  <span>{l}</span>
  <strong>{v}</strong>
 </div>
}

function Scanner({title,placeholder,value,setValue,onScan,loading,multi}:any){
 return <section>
  <div className="panel scanner">
   <h2>{title}</h2>
   <p>Results are evidence-based and do not guarantee safety.</p>

   {multi?
    <textarea value={value} onChange={e=>setValue(e.target.value)} placeholder={placeholder}/>:
    <input value={value} onChange={e=>setValue(e.target.value)} placeholder={placeholder}/>
   }

   <button className="scan" disabled={!value.trim()||loading} onClick={onScan}>
    {loading?'Analyzing...':'Run Defensive Scan'} <Search/>
   </button>
  </div>
 </section>
}

function Email({onResult,refresh}:any){
 const[s,setS]=useState(''),[b,setB]=useState(''),[l,setL]=useState(false);

 async function run(){
  setL(true);
  try{
   const r=await fetch(API+'/api/analyze/email',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({subject:s,body:b})
   });
   onResult(await r.json());
   refresh()
  }finally{
   setL(false)
  }
 }

 return <section>
  <div className="panel scanner">
   <h2>Analyze suspicious email</h2>
   <input value={s} onChange={e=>setS(e.target.value)} placeholder="Subject"/>
   <textarea value={b} onChange={e=>setB(e.target.value)} placeholder="Paste email body..."/>
   <button className="scan" disabled={!b.trim()||l} onClick={run}>
    {l?'Analyzing...':'Analyze Email'} <Mail/>
   </button>
  </div>
 </section>
}

function Result({result,close}:any){
 if(result.error)
  return <div className="modal">
   <div className="result">
    <button className="close" onClick={close}>×</button>
    <h2>Analysis error</h2>
    <p>{result.error}</p>
   </div>
  </div>;

 const bad=result.risk_score>=50;

 return <div className="modal">
  <div className="result">
   <button className="close" onClick={close}>×</button>

   <div className={'verdict '+(bad?'danger':'good')}>
    {bad?<AlertTriangle/>:<CheckCircle2/>}
    <div>
     <b>{result.verdict.replaceAll('_',' ')}</b>
     <small>Risk {result.risk_score}/100 · Confidence {result.confidence}%</small>
    </div>
   </div>

   <h3>Detection evidence</h3>

   {Array.from(
     new Map(
      (result.indicators||[]).map((i:any)=>[
       i.rule_id,
       i
      ])
     ).values()
    ).map((i:any,n:number)=>
     <div className="indicator" key={n}>
      <b>{i.rule_id}</b>
      <span>{i.explanation}</span>
      <em>+{i.score}</em>
     </div>
    )}

   <div className="recommend">
    <b>Recommended action</b>
    <p>{result.recommendation}</p>
   </div>
  </div>
 </div>
}

function HistoryView({history}:any){
 return <section>
  <div className="panel">
   <h2>Scan History</h2>

   {history.length?
    history.map(x=>
     <div className="hist" key={x.analysis_id}>
      <span>{x.input_type}</span>
      <b>{x.verdict.replaceAll('_',' ')}</b>
      <strong>{x.risk_score}/100</strong>
      <small>{new Date(x.timestamp).toLocaleString()}</small>
     </div>
    ):
    <p>No scans yet.</p>
   }
  </div>
 </section>
}

createRoot(document.getElementById('root')!).render(<App/>);
