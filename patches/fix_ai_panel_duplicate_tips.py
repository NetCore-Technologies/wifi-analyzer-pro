"""Fix the dashboard compile error and wire its main scan loop to the local API."""
from pathlib import Path

app_path = Path("src/App.jsx")
hook_path = Path("src/hooks/useWifiData.js")
app = app_path.read_text(encoding="utf-8")
hook = hook_path.read_text(encoding="utf-8")

changes = []

def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"Expected one match for {label}, found {count}; no files changed.")
    changes.append(label)
    return source.replace(old, new, 1)

# The component had two `tips` constants in the same scope, breaking every Vite build.
duplicate_tips = '''  const tips=[
    {Icon:Wifi,    col:C.cyan,   title:"Channel Recommendation",   body:"Switch to Channel 36 (5GHz) — only 22% utilisation vs Channel 6 at 78%. Expected throughput gain: ~120 Mbps."},
    {Icon:Shield,  col:C.red,    title:"Rogue AP Detected",        body:"DE:AD:BE:EF:00:01 is cloning ManitNet-AX3600. This is an Evil Twin attack. Isolate and investigate immediately."},
    {Icon:Activity,col:C.yellow, title:"Stability Issue",          body:"8.3% packet loss on wlan0. Likely cause: 2.4GHz interference from Ch 6 neighbours. Enable band steering."},
    {Icon:Zap,     col:C.green,  title:"Speed Optimisation",       body:"Enable 802.11k/v/r on AX10000 for roaming. Prioritise Pi 4B traffic via QoS — it handles all DNS for the network."},
  ];
'''
app = replace_once(app, duplicate_tips, "", "remove duplicate AiPanel tips declaration")

# Demo samples must never be converted into real security or health alerts.
app = replace_once(
    app,
    "function AiPanel({ networks: netsProp, devices: devsProp, diag, sysInfo }) {\n  const nets = netsProp || NETWORKS;\n  const devs = devsProp || DEVICES;",
    "function AiPanel({ networks: netsProp, devices: devsProp, diag, sysInfo, isLive = false }) {\n  const nets = isLive ? (netsProp || []) : [];\n  const devs = isLive ? (devsProp || []) : [];",
    "gate AI findings on live backend observations",
)
app = replace_once(app, "  const liveInsights = [", "  const liveInsights = isLive ? [", "mark AI findings as live-only")
app = replace_once(app, "  ].filter(Boolean).slice(0,4);", "  ].filter(Boolean).slice(0,4) : [];", "finish live-only AI findings expression")

# Replace the old canned channel/Evil-Twin/performance assertions with a neutral empty state.
import re
pattern = re.compile(r'  const tips = liveInsights\.length >= 2 \? liveInsights : \[\n.*?\n  \];\n  const summaryScore = liveInsights\.length >= 2 \? score : 91;\n  const isLive = liveInsights\.length >= 2;\n', re.S)
replacement = '''  const tips = liveInsights.length ? liveInsights : [
    {Icon:Info, col:C.cyan, title:"Awaiting live observations", body:"Connect the Wi-Fi Analyzer Pro local service to generate recommendations from measured scans and diagnostics. Demo samples are not security findings."},
  ];
  const summaryScore = isLive && diag ? score : null;
'''
app, ai_replacements = pattern.subn(replacement, app, count=1)
if ai_replacements != 1:
    raise SystemExit(f"Expected one canned AI recommendation block, found {ai_replacements}; no files changed.")
changes.append("remove canned AI security/performance findings and scores")

app = replace_once(
    app,
    'summaryScore>75?C.green:summaryScore>50?C.yellow:C.red',
    'summaryScore==null?C.cyan:summaryScore>75?C.green:summaryScore>50?C.yellow:C.red',
    "show a neutral AI status when no live score exists",
)
app = replace_once(
    app,
    '{summaryScore>75?"generally healthy":summaryScore>50?"moderate":"needs attention"}',
    '{summaryScore==null?"awaiting live observations":summaryScore>75?"generally healthy":summaryScore>50?"moderate":"needs attention"}',
    "avoid a false degraded-health message before live measurements",
)

app = replace_once(
    app,
    '<AiPanel networks={networks} devices={devices} diag={liveDiag} sysInfo={liveSystem}/>',
    '<AiPanel networks={networks} devices={devices} diag={liveDiag} sysInfo={liveSystem} isLive={liveMode}/>',
    "pass live mode into AI findings panel",
)

# All panels use one host-relative API URL, so a remote client talks to its own analyzer host.
app = replace_once(app, "const C = {", "const API_BASE = `${window.location.protocol}//${window.location.hostname}:199`;\n\nconst C = {", "add host-relative API base")

old_effect = '''  useEffect(()=>{
    async function autoDetect(){
      try{
        const r=await fetch("http://localhost:199/api/has_wifi",{signal:AbortSignal.timeout(3000)});
        const d=await r.json();
        if(d.has_wifi){
          setLiveMode(true);
          const [sr,dr,sysr,diagr]=await Promise.all([
            fetch("http://localhost:199/api/scan"),
            fetch("http://localhost:199/api/devices"),
            fetch("http://localhost:199/api/system"),
            fetch("http://localhost:199/api/diagnostics"),
          ]);
          const sd=await sr.json();const dd=await dr.json();
          const syd=await sysr.json();const dg=await diagr.json();
          if(sd.networks?.length)setLiveNets(sd.networks);
          if(dd.devices?.length)setLiveDevs(dd.devices);
          if(syd)setLiveSystem(syd);
          if(dg)setLiveDiag(dg);
        }
      }catch(_){}
      setChecking(false);
    }
    autoDetect();
    const iv=setInterval(async()=>{
      if(!liveMode)return;
      try{
        const [r,dr,dg]=await Promise.all([
          fetch("http://localhost:199/api/scan"),
          fetch("http://localhost:199/api/devices"),
          fetch("http://localhost:199/api/diagnostics"),
        ]);
        const d=await r.json();const dd=await dr.json();const diag=await dg.json();
        if(d.networks?.length)setLiveNets(d.networks);
        if(dd.devices?.length)setLiveDevs(dd.devices);
        if(diag)setLiveDiag(diag);
      }catch(_){}
    },10000);
    return()=>clearInterval(iv);
  },[]);
'''
new_effect = '''  useEffect(()=>{
    let disposed=false;
    const refreshLiveData=async()=>{
      try{
        const hasResponse=await fetch(`${API_BASE}/api/has_wifi`,{signal:AbortSignal.timeout(4000)});
        if(!hasResponse.ok)throw new Error(`Wi-Fi probe returned HTTP ${hasResponse.status}`);
        const availability=await hasResponse.json();
        if(!availability.has_wifi){
          if(!disposed)setLiveMode(false);
          return;
        }
        const responses=await Promise.all([
          fetch(`${API_BASE}/api/scan`,{signal:AbortSignal.timeout(15000)}),
          fetch(`${API_BASE}/api/devices`,{signal:AbortSignal.timeout(10000)}),
          fetch(`${API_BASE}/api/system`,{signal:AbortSignal.timeout(5000)}),
          fetch(`${API_BASE}/api/diagnostics`,{signal:AbortSignal.timeout(18000)}),
        ]);
        if(responses.some(response=>!response.ok))throw new Error("One or more local API requests failed");
        const [scanData,deviceData,systemData,diagnosticData]=await Promise.all(responses.map(response=>response.json()));
        if(disposed)return;
        setLiveMode(true);
        if(Array.isArray(scanData.networks))setLiveNets(scanData.networks);
        if(Array.isArray(deviceData.devices))setLiveDevs(deviceData.devices);
        setLiveSystem(systemData);
        setLiveDiag(diagnosticData);
      }catch(_error){
        if(!disposed)setLiveMode(false);
      }finally{
        if(!disposed)setChecking(false);
      }
    };
    refreshLiveData();
    const intervalId=setInterval(refreshLiveData,10000);
    return()=>{disposed=true;clearInterval(intervalId);};
  },[]);
'''
app = replace_once(app, old_effect, new_effect, "replace stale-closure polling loop with live refresh")

old_scan = '''  const scan=()=>{
    if(scanning)return;
    setScanning(true);
    setTimeout(()=>{setScanning(false);addToast("Scan complete — 7 networks found","success");},2200);
  };
'''
new_scan = '''  const scan=async()=>{
    if(scanning)return;
    setScanning(true);
    try{
      const response=await fetch(`${API_BASE}/api/scan`,{signal:AbortSignal.timeout(18000)});
      if(!response.ok)throw new Error(`HTTP ${response.status}`);
      const data=await response.json();
      if(!Array.isArray(data.networks))throw new Error("The scan endpoint returned an invalid response");
      setLiveNets(data.networks);
      setLiveMode(data.source!=="demo");
      addToast(`${data.source==="demo"?"Demo":"Live"} scan complete — ${data.networks.length} network(s) found`,data.source==="demo"?"info":"success");
    }catch(error){
      addToast(`Scan failed: ${error.message||"local backend unavailable"}`,"warning");
    }finally{
      setScanning(false);
    }
  };
'''
app = replace_once(app, old_scan, new_scan, "connect Scan button to the real API")

# Convert remaining legacy fetch literals (including the speed-test panel) safely.
import re
app, api_rewrites = re.subn(r'fetch\("http://localhost:199(/api/[^\"]+)"', r'fetch(`${API_BASE}\1`', app)
if api_rewrites < 1:
    raise SystemExit("No legacy API requests were found to migrate; no files changed.")
changes.append(f"migrate {api_rewrites} remaining API requests to the host-relative URL")

# Do not print a hard-coded interface name, RSSI or SNR as though it came from the adapter.
app = app.replace(
    '<span>LIVE · wlan0 · -42 dBm · SNR 45 dB</span>',
    '<span>{liveMode ? `LIVE · ${liveSystem?.wifi_interface || "Wi-Fi adapter detected"}` : "DEMO DATA · no live adapter connected"}</span>'
)

# Keep the alternate hook in sync; it is used by the dedicated analyzer page.
hook = hook.replace(
    "const API_BASE = window.location.port === '199'\n  ? `${window.location.protocol}//${window.location.hostname}:199`\n  : 'http://localhost:8765';",
    "const API_BASE = import.meta.env.VITE_API_BASE || `${window.location.protocol}//${window.location.hostname}:199`;"
)

# Ensure all changes are safe before writing either file.
if "const tips=[" in app and "const tips = liveInsights" in app:
    raise SystemExit("Duplicate tips declaration still present; no files changed.")
if 'fetch("http://localhost:199/api/' in app:
    raise SystemExit("A localhost-only API URL remains in App.jsx; no files changed.")
if "setTimeout(()=>{setScanning(false);addToast(\"Scan complete" in app:
    raise SystemExit("The mock scan action remains in App.jsx; no files changed.")

app_path.write_text(app, encoding="utf-8")
hook_path.write_text(hook, encoding="utf-8")
print("Applied:")
for change in changes:
    print(f"- {change}")
