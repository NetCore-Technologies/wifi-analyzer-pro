"""Correct old UI panels that displayed placeholders as live network findings."""
from __future__ import annotations

import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"UI patch expected one {label} anchor; found {count}")
    return text.replace(old, new, 1)


def patch_app(app: str) -> str:
    # Delete the old hand-authored alert feed. These were demo claims, not observations.
    app, removed = re.subn(r"const ALERTS_DATA = \[.*?\n\];\n\n", "", app, count=1, flags=re.S)
    if removed != 1 and "ALERTS_DATA" in app:
        raise SystemExit("Could not safely remove the legacy static alert list")

    builder = '''function buildObservedAlerts(networks, diagnostics) {
  const alerts = [];
  for (const network of Array.isArray(networks) ? networks : []) {
    const label = network.ssid || network.bssid || "Unnamed access point";
    const security = String(network.security ?? network.sec ?? "").toLowerCase();
    if (network.rogue === true) alerts.push({ type: "warning", msg: `Scanner flagged ${label} as a candidate anomaly; verify its BSSID manually.`, time: "Current scan" });
    if (security === "open") alerts.push({ type: "warning", msg: `Open network observed: ${label}. Confirm that this is expected before connecting.`, time: "Current scan" });
    if (network.rssi != null && Number.isFinite(Number(network.rssi)) && Number(network.rssi) <= -80) alerts.push({ type: "info", msg: `Weak measured signal for ${label}: ${Number(network.rssi)} dBm.`, time: "Current scan" });
  }
  const loss = Number(diagnostics?.packet_loss_pct);
  const latency = Number(diagnostics?.latency_ms);
  if (diagnostics && Number.isFinite(loss) && loss >= 5) alerts.push({ type: "warning", msg: `Measured packet loss is ${loss}%.`, time: "Latest diagnostic" });
  if (diagnostics && Number.isFinite(latency) && latency >= 100) alerts.push({ type: "warning", msg: `Measured latency is ${latency} ms.`, time: "Latest diagnostic" });
  return alerts.slice(0, 50);
}

'''
    if "function buildObservedAlerts(networks, diagnostics)" not in app:
        app = replace_once(app, "function AlertsPanel() {", builder + "function AlertsPanel({ alerts = [] }) {")
    app = replace_once(app,
        '  const filtered=filter==="all"?ALERTS_DATA:ALERTS_DATA.filter(a=>a.type===filter);',
        '  const filtered=filter==="all"?alerts:alerts.filter(a=>a.type===filter);',
        "alert feed source")

    stats_old = '''      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        <Stat label="Critical"  value="1" sub="Evil Twin active"   col={C.red}    Icon={XCircle}       delay={1}/>
        <Stat label="Warnings"  value="2" sub="Packet loss · Ch 6" col={C.yellow} Icon={AlertTriangle} delay={2}/>
        <Stat label="Info"      value="2" sub="New device · DNS"   col={C.cyan}   Icon={Info}          delay={3}/>
        <Stat label="Resolved"  value="2" sub="Last 2 hours"       col={C.green}  Icon={CheckCircle}   delay={4}/>
      </div>'''
    stats_new = '''      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        <Stat label="Critical" value={alerts.filter(a=>a.type==="danger").length} sub="Verified critical conditions" col={C.red} Icon={XCircle} delay={1}/>
        <Stat label="Warnings" value={alerts.filter(a=>a.type==="warning").length} sub="From current measurements" col={C.yellow} Icon={AlertTriangle} delay={2}/>
        <Stat label="Info" value={alerts.filter(a=>a.type==="info").length} sub="Advisories" col={C.cyan} Icon={Info} delay={3}/>
        <Stat label="Resolved" value="—" sub="No alert history stored" col={C.green} Icon={CheckCircle} delay={4}/>
      </div>'''
    app = replace_once(app, stats_old, stats_new, "alert counts")
    app = replace_once(app, '          {filtered.map((a,i)=>{',
        '          {filtered.length===0&&<div style={{padding:"16px 10px",color:C.muted,fontSize:12}}>No alert conditions were detected in the available measurements. This is not a guarantee that the network is secure.</div>}\n          {filtered.map((a,i)=>{',
        "empty alert state")
    app = replace_once(app, '            {ALERTS_DATA.slice(0,4).map((a,i)=>{',
        '            {alertsProp.slice(0,4).map((a,i)=>{', "dashboard alert data")
    app = replace_once(app,
        'function DashboardPanel({ rssiData, speedData, networks: netsProp, devices: devsProp, diag }) {',
        'function DashboardPanel({ rssiData, speedData, networks: netsProp, devices: devsProp, diag, alertsProp = [] }) {',
        "dashboard alert prop")

    # Decorative integration toggles were not connected to delivery services.
    integrations_old = '''      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
        {[
          {label:"Discord Webhook", desc:"Alert on rogue APs + outages",     on:true,  col:C.purple},
          {label:"Email (SMTP)",    desc:"Daily digest + critical only",      on:false, col:C.cyan},
          {label:"MQTT Broker",     desc:"Publish events to mqtt://broker",   on:true,  col:C.green},
        ].map((c,i)=>(
          <div key={i} className="hover-card" style={{...s.card,...s.bet}}>
            <div>
              <div style={{fontSize:12,fontWeight:600,color:C.text,marginBottom:2}}>{c.label}</div>
              <div style={{fontSize:10,color:C.muted}}>{c.desc}</div>
            </div>
            <div style={{width:38,height:21,borderRadius:11,background:c.on?c.col:C.border,
              position:"relative",cursor:"pointer",transition:"background 0.25s",flexShrink:0}}>
              <div style={{position:"absolute",top:2.5,left:c.on?19:2.5,width:16,height:16,
                borderRadius:"50%",background:"white",transition:"left 0.25s"}}/>
            </div>
          </div>
        ))}
      </div>'''
    app = replace_once(app, integrations_old,
        '      <div style={{...s.card,fontSize:12,color:C.muted}}>Alert delivery integrations are not configured in this build. Events shown above are local observations only.</div>',
        "inactive integration toggles")

    # A hard-coded SSID clone allegation and an invented airtime percentage are not valid findings.
    wireless_old = '''      <div style={{...s.row,gap:10}}>
        <div style={{...s.row,gap:8,padding:"10px 14px",background:C.redFaint,border:`1px solid ${C.red}44`,borderRadius:8,animation:"borderPulse 2s ease-in-out infinite"}}>
          <AlertTriangle size={14} color={C.red}/>
          <span style={{fontSize:12,color:C.red,fontWeight:600}}>Evil Twin Detected — DE:AD:BE:EF:00:01 is cloning ManitNet-AX3600. Do not connect.</span>
        </div>
        <div style={{...s.row,gap:8,padding:"10px 14px",background:C.greenFaint,border:`1px solid ${C.green}33`,borderRadius:8}}>
          <CheckCircle size={14} color={C.green}/>
          <span style={{fontSize:12,color:C.green}}>Best channel: 36 (5GHz) — only 22% utilised</span>
        </div>
      </div>'''
    app = replace_once(app, wireless_old,
        '      <div style={{...s.card,fontSize:11,color:C.muted}}>SSID similarity alone does not prove an Evil Twin. Compare observations against BSSIDs you explicitly trust. Channel counts are nearby BSS observations, not measured airtime utilisation.</div>',
        "fabricated rogue AP banner")

    # Make the wireless table explicitly distinguish live observations from demo samples.
    app = replace_once(app, 'function WirelessPanel({ networks: netsProp }) {',
        'function WirelessPanel({ networks: netsProp, isLive = false }) {', "wireless panel live-mode prop")
    nets_old = '''  const nets=[...NETS]
    .filter(n=>n.ssid.toLowerCase().includes(filter.toLowerCase())||n.bssid.toLowerCase().includes(filter.toLowerCase()))
    .sort((a,b)=>sort==="rssi"?a.rssi-b.rssi:sort==="snr"?b.snr-a.snr:a.ch-b.ch);
'''
    nets_new = '''  const nets=[...NETS]
    .filter(n=>(n.ssid||"").toLowerCase().includes(filter.toLowerCase())||(n.bssid||"").toLowerCase().includes(filter.toLowerCase()))
    .sort((a,b)=>sort==="rssi"?(Number(a.rssi??-200)-Number(b.rssi??-200)):sort==="snr"?(Number(b.snr??-Infinity)-Number(a.snr??-Infinity)):Number(a.ch??0)-Number(b.ch??0));
  const observedChannels=[...new Set(NETS.filter(n=>n.band&&Number(n.ch??n.channel)>0).map(n=>`${n.band}:${Number(n.ch??n.channel)}`))]
    .map(value=>{const [band,channel]=value.split(":");return {band,channel:Number(channel),count:NETS.filter(n=>n.band===band&&Number(n.ch??n.channel)===Number(channel)).length};})
    .sort((a,b)=>a.count-b.count||a.band.localeCompare(b.band)||a.channel-b.channel);
  const leastObserved=observedChannels[0]||null;
'''
    app = replace_once(app, nets_old, nets_new, "wireless safe filtering and observed-channel ranking")
    stats_old = '''        <Stat label="APs Found" value={NETS.length} sub={`${NETS.filter(n=>n.band==="5GHz").length}×5GHz · ${NETS.filter(n=>n.band==="2.4GHz").length}×2.4GHz`} col={C.cyan} Icon={Wifi} delay={1}/>
        <Stat label="Rogue APs" value={NETS.filter(n=>n.rogue).length} sub={NETS.filter(n=>n.rogue).length>0?"Evil Twin active — investigate":"None detected"} col={NETS.filter(n=>n.rogue).length>0?C.red:C.green} Icon={Shield} delay={2}/>
        <Stat label="Best Channel" value={`Ch ${NETS.length?[...NETS].sort((a,b)=>a.rssi-b.rssi)[0]?.ch||36:36}`} sub="Least congested" col={C.green} Icon={ScanLine} delay={3}/>
        <Stat label="Strongest" value={`${NETS.length?Math.max(...NETS.map(n=>n.rssi)):-42} dBm`} sub={NETS.length?[...NETS].sort((a,b)=>b.rssi-a.rssi)[0]?.ssid||"":"No scan"} col={C.purple} Icon={Rss} delay={4}/>
'''
    stats_new = '''        <Stat label="BSS records" value={NETS.length} sub={`${NETS.filter(n=>n.band==="2.4GHz").length}×2.4 · ${NETS.filter(n=>n.band==="5GHz").length}×5 · ${NETS.filter(n=>n.band==="6GHz").length}×6 GHz`} col={C.cyan} Icon={Wifi} delay={1}/>
        <Stat label="Scanner flags" value={NETS.filter(n=>n.rogue===true).length} sub="Candidate metadata only; verify BSSIDs manually" col={C.yellow} Icon={Shield} delay={2}/>
        <Stat label="Least observed" value={leastObserved?`${leastObserved.channel} · ${leastObserved.band}`:"—"} sub={leastObserved?`${leastObserved.count} observed BSS; not airtime utilisation":"No channel observations"} col={C.green} Icon={ScanLine} delay={3}/>
        <Stat label="Strongest" value={NETS.some(n=>n.rssi!=null)?`${Math.max(...NETS.filter(n=>n.rssi!=null).map(n=>Number(n.rssi)))} dBm`:"—"} sub={NETS.some(n=>n.rssi!=null)?([...NETS].filter(n=>n.rssi!=null).sort((a,b)=>Number(b.rssi)-Number(a.rssi))[0]?.ssid||"Observed BSS"):"No signal measurement"} col={C.purple} Icon={Rss} delay={4}/>
'''
    app = replace_once(app, stats_old, stats_new, "wireless stat accuracy")
    app = replace_once(app, '<SHdr title="Live WiFi Scan" sub={`Auto-refresh every 10s · ${nets.length} networks`}/>',
        '<SHdr title={isLive?"Observed Wi-Fi scan":"Wi-Fi scan demo preview"} sub={isLive?`${nets.length} observed BSS records · source: local scanner`:`${nets.length} illustrative records · not live RF observations`}/>',
        "wireless scan provenance")
    app = replace_once(app, '<td style={{padding:"9px 10px",...s.mono,color:n.snr>30?C.green:n.snr>20?C.yellow:C.red}}>{n.snr} dB</td>',
        '<td style={{padding:"9px 10px",...s.mono,color:n.snr==null?C.muted:n.snr>30?C.green:n.snr>20?C.yellow:C.red}}>{n.snr==null?"—":`${n.snr} dB`}</td>',
        "missing SNR display")
    app = replace_once(app, '<td style={{padding:"9px 10px"}}><AnimatedBars rssi={n.rssi}/></td>',
        '<td style={{padding:"9px 10px"}}>{n.rssi==null?<span style={{color:C.muted}}>—</span>:<AnimatedBars rssi={n.rssi}/>}</td>',
        "missing RSSI display")
    app = replace_once(app, 'wireless:    <WirelessPanel networks={networks}/>,',
        'wireless:    <WirelessPanel networks={networks} isLive={liveMode}/>,', "wireless panel live flag")
    app = replace_once(app, '<SHdr title="Nearby Networks" sub="7 found · best ch: 36 (5GHz)"/>',
        '<SHdr title="Nearby Networks" sub={`${(netsProp||NETWORKS).length} records in current view`}/>',
        "dashboard nearby network count")

    # Make Alerts and Dashboard consume only actual live API observations.
    app = replace_once(app, '  const networks=Array.isArray(liveNets) ? liveNets.map(toUiNetwork) : NETWORKS;\n  const devices=Array.isArray(liveDevs) ? liveDevs.map(toUiDevice) : DEVICES;',
        '  const networks=Array.isArray(liveNets) ? liveNets.map(toUiNetwork) : NETWORKS;\n  const devices=Array.isArray(liveDevs) ? liveDevs.map(toUiDevice) : DEVICES;\n  const observedAlerts=liveMode?buildObservedAlerts(networks,liveDiag):[];',
        "observed alert generation")
    app = replace_once(app, 'dashboard:   <DashboardPanel rssiData={rssiData} speedData={speedData} networks={networks} devices={devices} diag={liveDiag}/>,',
        'dashboard:   <DashboardPanel rssiData={rssiData} speedData={speedData} networks={networks} devices={devices} diag={liveDiag} alertsProp={observedAlerts}/>,',
        "dashboard alert props")
    app = replace_once(app, 'alerts:      <AlertsPanel/>,', 'alerts:      <AlertsPanel alerts={observedAlerts}/>,', "alerts panel props")
    app = replace_once(app, '          <SHdr title="Active Alerts" right={<Tag text="7 TOTAL" col={C.yellow}/>}/>',
        '          <SHdr title="Observed Alerts" right={<Tag text={`${alertsProp.length} ACTIVE`} col={C.yellow}/>}/>',
        "dashboard alert heading")

    # Rename static demonstration graphs honestly instead of presenting them as live samples.
    app = replace_once(app, '<SHdr title="Live Signal History" sub="wlan0 · ManitNet-AX3600 · auto-refresh 2s"/>',
        '<SHdr title="Signal history preview" sub="Illustrative sample values; not measured from this adapter"/>',
        "signal preview provenance")
    app = replace_once(app, '<SHdr title="Live RSSI" sub="wlan0 · 40 samples"/>',
        '<SHdr title="RSSI preview" sub="Illustrative sample values; run a live scan for observations"/>',
        "RSSI preview provenance")
    app = replace_once(app, '<SHdr title="SNR History" sub="Signal-to-Noise Ratio"/>',
        '<SHdr title="SNR preview" sub="Illustrative values; actual SNR requires a measured noise floor"/>',
        "SNR preview provenance")
    app = replace_once(app, '<SHdr title="Channel Utilisation" sub="2.4 + 5 GHz"/>',
        '<SHdr title="Channel density preview" sub="Illustrative BSS counts; not measured airtime utilisation"/>',
        "channel preview provenance")
    app = replace_once(app,
        '<span style={{fontSize:12,color:C.green}}>Stable — predicted -41 to -48 dBm next 10 samples</span>',
        '<span style={{fontSize:12,color:C.green}}>Signal trend prediction is not available from this sample chart</span>',
        "remove invented signal prediction")

    # Static signal score tiles and summary values are not measurements.
    scores_old = '''  const scores=[
    {label:"Signal Quality",     val:94, col:C.green},
    {label:"Stability",          val:88, col:C.cyan},
    {label:"Reliability",        val:91, col:C.purple},
    {label:"Overall Health",     val:91, col:C.green},
  ];
'''
    scores_new = '''  const scores=[
    {label:"Signal Quality", val:null, col:C.green},
    {label:"Stability", val:null, col:C.cyan},
    {label:"Reliability", val:null, col:C.purple},
    {label:"Overall Health", val:null, col:C.green},
  ];
'''
    app = replace_once(app, scores_old, scores_new, "remove invented signal scores")
    signal_score_old = '''<span style={{fontSize:26,fontWeight:700,color:sc.col,animation:"countUp 0.5s ease both"}}>{sc.val}</span>
              <span style={{fontSize:12,color:C.muted}}>/100</span>'''
    signal_score_new = '''<span style={{fontSize:26,fontWeight:700,color:sc.col,animation:"countUp 0.5s ease both"}}>{sc.val==null?"—":sc.val}</span>
              <span style={{fontSize:12,color:C.muted}}>{sc.val==null?"not measured":"/100"}</span>'''
    app = replace_once(app, signal_score_old, signal_score_new, "signal score empty state")
    app = replace_once(app, 'width:`${sc.val}%`', 'width:`${sc.val==null?0:sc.val}%`', "signal score progress safe state")
    app = replace_once(app, '{" "}Overall score: <span style={{color:C.cyan,fontWeight:700}}>{summaryScore}/100</span>.',
        '{summaryScore==null?" Overall score unavailable until live diagnostics are received.":<> Overall score: <span style={{color:C.cyan,fontWeight:700}}>{summaryScore}/100</span>.</>}',
        "AI summary score empty state")

    # Speed numbers are only meaningful after a successful measurement.
    app = replace_once(app, 'function SpeedPanel({ speedData }) {',
        'function SpeedPanel({ speedData }) {\n  const [testError,setTestError]=useState("");', "speed test error state")
    app = replace_once(app,
        '    setRunning(true);setPct(0);setPhase("download");setRealDl(null);setRealUl(null);setRealPing(null);',
        '    setRunning(true);setPct(0);setPhase("download");setTestError("");setRealDl(null);setRealUl(null);setRealPing(null);',
        "clear previous speed test error")
    speed_result_old = '''      const d=await r.json();
      clearInterval(t);setPct(100);setPhase("done");
      setRealDl(d.download);setRealUl(d.upload);setRealPing(d.ping);
    }catch{
      clearInterval(t);setPct(100);setPhase("done");
    }
    setRunning(false);
  };
  const dlVal=phase==="done"&&realDl!=null?realDl:running?(pct/100*924).toFixed(0):924;
  const ulVal=phase==="done"&&realUl!=null?realUl:running&&pct>50?((pct-50)/50*421).toFixed(0):(phase==="done"?421:0);'''
    speed_result_new = '''      if(!r.ok)throw new Error(`Speed test returned HTTP ${r.status}`);
      const d=await r.json();
      if(d.error)throw new Error(d.error);
      const download=Number(d.download), upload=Number(d.upload), ping=Number(d.ping);
      if(![download,upload,ping].every(v=>Number.isFinite(v)&&v>=0))throw new Error("Speed test returned invalid measurements");
      clearInterval(t);setPct(100);setPhase("done");
      setRealDl(download);setRealUl(upload);setRealPing(ping);
    }catch(error){
      clearInterval(t);setPct(100);setPhase("error");setTestError(error.message||"Speed test failed");
    }
    setRunning(false);
  };
  const dlVal=phase==="done"&&realDl!=null?realDl:running?"…":"—";'''
    app = replace_once(app, speed_result_old, speed_result_new, "speed test result validation")
    speed_stats_old = '''        <Stat label="Download" value="924 Mbps" sub="NBN 1000 · 92.4% efficiency" col={C.cyan}   Icon={ArrowDown} delay={1}/>
        <Stat label="Upload"   value="421 Mbps" sub="Full duplex"                   col={C.purple} Icon={ArrowUp}   delay={2}/>
        <Stat label="Ping"     value="8ms"       sub="Jitter: 1.2ms"                col={C.green}  Icon={Activity}  delay={3}/>
        <Stat label="Bufferbloat" value="A+"     sub="Excellent under load"          col={C.green}  Icon={Gauge}     delay={4}/>'''
    speed_stats_new = '''        <Stat label="Download" value={realDl==null?"—":`${realDl} Mbps`} sub="Latest completed test" col={C.cyan} Icon={ArrowDown} delay={1}/>
        <Stat label="Upload" value={realUl==null?"—":`${realUl} Mbps`} sub="Latest completed test" col={C.purple} Icon={ArrowUp} delay={2}/>
        <Stat label="Ping" value={realPing==null?"—":`${realPing} ms`} sub="Single reachability timing" col={C.green} Icon={Activity} delay={3}/>
        <Stat label="Bufferbloat" value="Not measured" sub="No loaded-latency test is run" col={C.muted} Icon={Gauge} delay={4}/>'''
    app = replace_once(app, speed_stats_old, speed_stats_new, "speed stats")
    app = replace_once(app, '    <div style={{...s.col,gap:14}}>\n      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>\n        <Stat label="Download" value={realDl==null?"—":`${realDl} Mbps`}',
        '    <div style={{...s.col,gap:14}}>\n      {testError&&<div role="alert" style={{...s.card,border:`1px solid ${C.red}55`,color:C.red,fontSize:12}}>{testError}</div>}\n      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>\n        <Stat label="Download" value={realDl==null?"—":`${realDl} Mbps`}',
        "speed test error message")
    app = replace_once(app, '<SHdr title="Speed History" sub="Last 24 tests"/>',
        '<SHdr title="Speed history" sub="Illustrative values; use completed tests for measurements"/>',
        "speed chart provenance")
    app = replace_once(app, '                {running?(phase==="upload"?"UPLOAD":"DOWNLOAD"):phase==="done"?"DONE":"DOWNLOAD"}',
        '                {running?(phase==="upload"?"UPLOAD":"DOWNLOAD"):phase==="done"?"DONE":phase==="error"?"FAILED":"READY"}',
        "speed test phase label")

    # Remove guessed platform values from the System panel.
    app = replace_once(app, '  const cpu = sysInfo?.cpu_pct ?? 23;\n  const ram = sysInfo?.ram_pct ?? 61;\n  const temp = sysInfo?.cpu_temp ?? 48;\n  const disk = sysInfo?.disk_pct ?? 38;',
        '  const cpu = sysInfo?.cpu_pct ?? null;\n  const ram = sysInfo?.ram_pct ?? null;\n  const temp = sysInfo?.cpu_temp ?? null;\n  const disk = sysInfo?.disk_pct ?? null;', "system metrics")
    app = replace_once(app,
        '    {label:"CPU",  val:cpu,  col:C.cyan,   unit:"%",  detail:sysInfo?.cpu_model||"i5-6200U · 2.3 GHz"},\n    {label:"RAM",  val:ram,  col:C.purple, unit:"%",  detail:`${sysInfo?.ram_used_gb||"4.9"} GB / ${sysInfo?.ram_total_gb||"8"} GB`},\n    {label:"Temp", val:temp, col:C.yellow, unit:"°C", detail:`Throttle at ${sysInfo?.temp_max||80}°C`},\n    {label:"Disk", val:disk, col:C.green,  unit:"%",  detail:`${sysInfo?.disk_used_gb||"97"} GB / ${sysInfo?.disk_total_gb||"256"} GB`},',
        '    {label:"CPU", val:cpu, col:C.cyan, unit:"%", detail:sysInfo?.cpu_model||"Unavailable"},\n    {label:"RAM", val:ram, col:C.purple, unit:"%", detail:sysInfo?`${sysInfo.ram_used_gb??"—"} GB / ${sysInfo.ram_total_gb??"—"} GB`:"Unavailable"},\n    {label:"Temp", val:temp, col:C.yellow, unit:"°C", detail:temp==null?"Sensor unavailable":`Reported threshold ${sysInfo?.temp_max??"—"}°C`},\n    {label:"Disk", val:disk, col:C.green, unit:"%", detail:sysInfo?`${sysInfo.disk_used_gb??"—"} GB / ${sysInfo.disk_total_gb??"—"} GB`:"Unavailable"},',
        "system metric labels")
    app = replace_once(app, '>{g.val}<span style={{fontSize:11,fontWeight:400}}>{g.unit}</span></span>',
        '>{g.val==null?"—":g.val}<span style={{fontSize:11,fontWeight:400}}>{g.val==null?"":g.unit}</span></span>', "system unknown metric display")
    app = replace_once(app, 'width:`${g.val}%`', 'width:`${g.val==null?0:g.val}%`', "system gauge width")
    app = replace_once(app, 'sysInfo?`${sysInfo.os||"Linux"} · ${sysInfo.hostname||"localhost"}`:"ThinkPad X1 Carbon Gen 5 · Linux Mint 22.3"',
        'sysInfo?`${sysInfo.os||"—"} · ${sysInfo.hostname||"—"}`:"Live system data unavailable"', "system identity display")
    app = replace_once(app,
        '["OS", sysInfo?.os||"Linux Mint 22.3"],\n            ["CPU", sysInfo?.cpu_model||"Intel i5-6200U · 2.3 GHz"],\n            ["Memory", `${sysInfo?.ram_total_gb||8} GB`],\n            ["Disk", `${sysInfo?.disk_total_gb||256} GB`],\n            ["Uptime", sysInfo?.uptime||"N/A"],\n            ["WiFi Adapter", sysInfo?.wifi_adapter||"Intel 8260 (iwlwifi)"],',
        '["OS", sysInfo?.os||"Unavailable"],\n            ["CPU", sysInfo?.cpu_model||"Unavailable"],\n            ["Memory", sysInfo?.ram_total_gb==null?"Unavailable":`${sysInfo.ram_total_gb} GB`],\n            ["Disk", sysInfo?.disk_total_gb==null?"Unavailable":`${sysInfo.disk_total_gb} GB`],\n            ["Uptime", sysInfo?.uptime||"Unavailable"],\n            ["WiFi Adapter", sysInfo?.wifi_adapter||"Unavailable"],',
        "system info placeholders")

    # Feature grids list roadmap placeholders, so they must not display green completed checks.
    app = replace_once(app, '<CheckCircle size={11} color={col}/>', '<Info size={11} color={C.muted}/>', "feature preview icon")
    app = replace_once(app, '{badge&&<Tag text={badge} col={col}/>}', '<Tag text="CAPABILITY PREVIEW" col={C.muted}/>', "feature preview badge")

    if "ALERTS_DATA" in app:
        raise SystemExit("Static alert data remains in App.jsx")
    return app


def main() -> int:
    from pathlib import Path
    root = Path.cwd()
    app_path = root / "src" / "App.jsx"
    if not app_path.is_file():
        raise SystemExit("Run this script from the WiFi Analyzer Pro repository root")
    original = app_path.read_text(encoding="utf-8")
    patched = patch_app(original)
    if patched != original:
        app_path.write_text(patched, encoding="utf-8")
        print("Updated live-observation provenance and removed misleading placeholder claims.")
    else:
        print("UI integrity patch already applied; no changes needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
