import { useState, useEffect, useRef, useCallback } from "react";
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import {
  Wifi, Activity, Globe, Zap, Monitor, Radio, Layers,
  Smartphone, BarChart2, Download, Bell, Bot, Map, Wrench, Code,
  RefreshCw, Shield, AlertTriangle, CheckCircle, XCircle, Info,
  Lock, Server, LayoutDashboard, ArrowDown, ArrowUp,
  Cpu, HardDrive, Thermometer, Database, Signal, Search,
  Settings, Gauge, Network, Eye, Rss, ScanLine, ChevronRight,
  Moon, Sun, Menu, X, Terminal, Package, Antenna, FileSearch
} from "lucide-react";
import { apiFetch } from "./lib/api.js";
import FeatureWorkbench from "./components/FeatureWorkbench.jsx";
import RouterAgentConsole from "./components/RouterAgentConsole.jsx";
import PcapAnalyzer from "./components/PcapAnalyzer.jsx";
import { useAuth } from "./auth/AuthContext.jsx";

const API_BASE = `${window.location.protocol}//${window.location.hostname}:199`;

const C = {
  bg: "#070b14", card: "#0c1120", card2: "#111827",
  border: "#1e2d47", borderHov: "#2a3f65",
  cyan: "#06d6f0", cyanFaint: "rgba(6,214,240,0.1)", cyanMid: "rgba(6,214,240,0.22)",
  purple: "#a855f7", purpleFaint: "rgba(168,85,247,0.12)",
  green: "#22c55e", greenFaint: "rgba(34,197,94,0.1)",
  yellow: "#f59e0b", yellowFaint: "rgba(245,158,11,0.1)",
  red: "#ef4444", redFaint: "rgba(239,68,68,0.1)",
  blue: "#3b82f6",
  text: "#e2e8f0", textSec: "#94a3b8", muted: "#64748b",
};

const ANIM = `
  @keyframes fadeSlideIn {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.35; }
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
  @keyframes radarSweep {
    from { transform: rotate(0deg); }
    to   { transform: rotate(360deg); }
  }
  @keyframes ripple {
    0%   { transform: scale(0.8); opacity: 0.9; }
    100% { transform: scale(2.4); opacity: 0; }
  }
  @keyframes glow {
    0%, 100% { box-shadow: 0 0 6px rgba(6,214,240,0.4); }
    50%       { box-shadow: 0 0 18px rgba(6,214,240,0.8); }
  }
  @keyframes scanLine {
    0%   { transform: translateY(0); opacity: 0.9; }
    100% { transform: translateY(60px); opacity: 0; }
  }
  @keyframes slideInRight {
    from { opacity: 0; transform: translateX(24px); }
    to   { opacity: 1; transform: translateX(0); }
  }
  @keyframes countUp {
    from { opacity: 0; transform: scale(0.85); }
    to   { opacity: 1; transform: scale(1); }
  }
  @keyframes borderPulse {
    0%, 100% { border-color: rgba(6,214,240,0.3); }
    50%       { border-color: rgba(6,214,240,0.8); }
  }
  .anim-fade { animation: fadeSlideIn 0.35s ease both; }
  .anim-fade-d1 { animation: fadeSlideIn 0.35s 0.04s ease both; }
  .anim-fade-d2 { animation: fadeSlideIn 0.35s 0.08s ease both; }
  .anim-fade-d3 { animation: fadeSlideIn 0.35s 0.12s ease both; }
  .anim-fade-d4 { animation: fadeSlideIn 0.35s 0.16s ease both; }
  .anim-fade-d5 { animation: fadeSlideIn 0.35s 0.20s ease both; }
  .anim-slide-r { animation: slideInRight 0.3s ease both; }
  .hover-card:hover {
    border-color: ${C.borderHov} !important;
    transform: translateY(-1px);
    transition: all 0.18s;
  }
  .nav-btn:hover { background: rgba(6,214,240,0.06) !important; }
  .nav-btn.active { background: rgba(6,214,240,0.12) !important; border-left-color: ${C.cyan} !important; color: ${C.cyan} !important; }
`;

const NETWORKS = [
  { ssid:"ManitNet-AX3600", bssid:"A4:11:62:AA:BB:CC", rssi:-42, snr:45, ch:36, band:"5GHz",  sec:"WPA3", vendor:"Xiaomi",    wifi:"6",  rogue:false, clients:8, width:"80MHz" },
  { ssid:"ManitNet-6GHz",   bssid:"A4:11:62:AA:BB:DD", rssi:-45, snr:42, ch:37, band:"6GHz",  sec:"WPA3", vendor:"Xiaomi",    wifi:"6E", rogue:false, clients:2, width:"160MHz"},
  { ssid:"Optus_5G_Home",   bssid:"BC:EE:7B:11:22:33", rssi:-58, snr:28, ch:6,  band:"2.4GHz",sec:"WPA2", vendor:"Huawei",    wifi:"5",  rogue:false, clients:3, width:"20MHz" },
  { ssid:"ASUS_AX88U",      bssid:"E0:3F:49:CC:DD:EE", rssi:-65, snr:22, ch:100,band:"5GHz",  sec:"WPA3", vendor:"ASUS",      wifi:"6E", rogue:false, clients:5, width:"160MHz"},
  { ssid:"(hidden network)",bssid:"DE:AD:BE:EF:00:01",  rssi:-71, snr:14, ch:1,  band:"2.4GHz",sec:"Open", vendor:"Unknown",   wifi:"4",  rogue:true,  clients:0, width:"20MHz" },
  { ssid:"TPG-Home-WiFi",   bssid:"FC:EC:DA:44:55:66",  rssi:-74, snr:11, ch:11, band:"2.4GHz",sec:"WPA2", vendor:"TP-Link",   wifi:"5",  rogue:false, clients:2, width:"20MHz" },
  { ssid:"Neighbour_NBN",   bssid:"AA:BB:CC:77:88:99",  rssi:-79, snr:8,  ch:48, band:"5GHz",  sec:"WPA2", vendor:"Netgear",   wifi:"5",  rogue:false, clients:4, width:"40MHz" },
];

const DEVICES = [
  { name:"ThinkPad X1 C5",   mac:"A8:93:4A:11:22:33", ip:"192.168.1.10",  vendor:"Lenovo",       type:"Laptop",   rssi:-42, online:true,  bw:45.2, gw:false },
  { name:"Xiaomi AX10000",    mac:"A4:11:62:DD:EE:FF", ip:"192.168.1.1",   vendor:"Xiaomi",       type:"Router",   rssi:-18, online:true,  bw:0.4,  gw:true  },
  { name:"Pi 4B — AdGuard",   mac:"DC:A6:32:77:88:99", ip:"172.19.137.189",vendor:"Raspberry Pi", type:"Server",   rssi:-38, online:true,  bw:3.8,  gw:false },
  { name:"Galaxy Watch 6",    mac:"B4:EF:1C:44:55:66", ip:"192.168.1.11",  vendor:"Samsung",      type:"Wearable", rssi:-51, online:true,  bw:1.2,  gw:false },
  { name:"ESP32-S3 Cam",      mac:"CC:50:E3:AA:BB:CC", ip:"192.168.1.20",  vendor:"Espressif",    type:"IoT",      rssi:-67, online:true,  bw:0.8,  gw:false },
  { name:"Unknown Device",    mac:"DE:AD:BE:EF:CA:FE", ip:"192.168.1.99",  vendor:"???",          type:"Unknown",  rssi:-81, online:false, bw:0,    gw:false },
];

function toUiNetwork(network) {
  const rssi = network?.rssi == null ? null : Number(network.rssi);
  const snr = network?.snr == null ? null : Number(network.snr);
  const width = network?.width_mhz ?? network?.width ?? null;
  return {
    ...network,
    ssid: typeof network?.ssid === "string" ? network.ssid : "",
    bssid: typeof network?.bssid === "string" ? network.bssid : "",
    band: network?.band || "Unknown",
    ch: network?.channel ?? network?.ch ?? null,
    sec: network?.security ?? network?.sec ?? "Unknown",
    width: width == null ? "—" : (typeof width === "number" ? `${width}MHz` : String(width)),
    wifi: network?.wifi_generation ?? network?.wifi ?? "Unknown",
    clients: network?.clients ?? "—",
    vendor: network?.vendor || "Unknown",
    rssi: Number.isFinite(rssi) ? rssi : null,
    snr: Number.isFinite(snr) ? snr : null,
    rogue: network?.rogue === true,
  };
}

function toUiDevice(device) {
  return {
    ...device,
    name: device?.hostname || device?.name || device?.ip || "Unknown host",
    ip: device?.ip || "—",
    mac: device?.mac || "—",
    vendor: device?.vendor || "Unknown vendor",
    type: device?.type || "Unknown",
    online: typeof device?.online === "boolean" ? device.online : null,
    bw: device?.bw == null ? null : Number(device.bw),
    rssi: device?.rssi == null ? null : Number(device.rssi),
    gw: typeof device?.gw === "boolean" ? device.gw : false,
  };
}

const sin = (i, o = 0) => Math.sin(i * 0.4 + o) * 0.5 + 0.5;
const rand = () => (Math.random() - 0.5);
const genRSSI  = () => Array.from({length:40},(_,i)=>({ t:i, rssi:-(42+sin(i)*10+rand()*4), snr:38+sin(i,1)*10+rand()*3 }));
const genSpeed = () => Array.from({length:24},(_,i)=>({ t:i, dl:890+sin(i,2)*80+rand()*40, ul:415+sin(i,3)*40+rand()*20 }));
const s = {
  flex: {display:"flex"},
  col:  {display:"flex",flexDirection:"column"},
  row:  {display:"flex",alignItems:"center"},
  bet:  {display:"flex",alignItems:"center",justifyContent:"space-between"},
  cen:  {display:"flex",alignItems:"center",justifyContent:"center"},
  card: {background:C.card,border:`1px solid ${C.border}`,borderRadius:10,padding:"14px 16px",transition:"all 0.18s"},
  mono: {fontFamily:"'Courier New',Courier,monospace",fontSize:12},
  badge:(col)=>({background:col+"22",color:col,fontSize:10,fontWeight:700,padding:"2px 7px",borderRadius:4,letterSpacing:0.5,whiteSpace:"nowrap"}),
};

function AnimatedBars({ rssi }) {
  const pct = Math.max(0,Math.min(100,((rssi+100)/70)*100));
  const col = rssi>-55?C.green:rssi>-70?C.yellow:C.red;
  return (
    <div style={{...s.row,gap:6}}>
      <div style={{width:56,height:5,background:C.border,borderRadius:3,overflow:"hidden"}}>
        <div style={{width:`${pct}%`,height:"100%",background:col,borderRadius:3,transition:"width 0.6s cubic-bezier(.4,0,.2,1)"}}/>
      </div>
      <span style={{...s.mono,color:col,minWidth:34,fontSize:11}}>{rssi}</span>
    </div>
  );
}

function PulseDot({ col = C.green, size = 7 }) {
  return (
    <div style={{position:"relative",width:size,height:size,flexShrink:0}}>
      <div style={{position:"absolute",inset:0,borderRadius:"50%",background:col,animation:"pulse 1.4s ease-in-out infinite"}}/>
    </div>
  );
}

function Stat({ label, value, sub, col = C.cyan, Icon, delay = 0 }) {
  return (
    <div className={`hover-card anim-fade-d${delay}`}
      style={{...s.card,...s.col,gap:6}}>
      <div style={{...s.bet}}>
        <span style={{fontSize:10,color:C.muted,letterSpacing:0.8,fontWeight:600}}>{label.toUpperCase()}</span>
        {Icon && <Icon size={13} color={col} />}
      </div>
      <span style={{fontSize:22,fontWeight:700,color:col,letterSpacing:-0.5,animation:"countUp 0.4s ease both"}}>{value}</span>
      {sub && <span style={{fontSize:11,color:C.textSec}}>{sub}</span>}
    </div>
  );
}

function SHdr({ title, sub, right }) {
  return (
    <div style={{...s.bet,marginBottom:12}}>
      <div>
        <div style={{fontSize:14,fontWeight:600,color:C.text}}>{title}</div>
        {sub && <div style={{fontSize:11,color:C.muted,marginTop:1}}>{sub}</div>}
      </div>
      {right}
    </div>
  );
}

function Tag({ text, col }) {
  return <span style={s.badge(col)}>{text}</span>;
}

function RadarWidget({ scanning }) {
  return (
    <div style={{position:"relative",width:48,height:48,flexShrink:0}}>
      <svg width="48" height="48" viewBox="0 0 48 48" style={{position:"absolute",inset:0}}>
        <circle cx="24" cy="24" r="21" fill="none" stroke={C.cyanMid} strokeWidth="1"/>
        <circle cx="24" cy="24" r="14" fill="none" stroke={C.cyanMid} strokeWidth="0.7"/>
        <circle cx="24" cy="24" r="7"  fill="none" stroke={C.cyanMid} strokeWidth="0.5"/>
        <line x1="3" y1="24" x2="45" y2="24" stroke={C.border} strokeWidth="0.5"/>
        <line x1="24" y1="3" x2="24" y2="45" stroke={C.border} strokeWidth="0.5"/>
      </svg>
      {scanning && (
        <svg width="48" height="48" viewBox="0 0 48 48"
          style={{position:"absolute",inset:0,transformOrigin:"24px 24px",animation:"radarSweep 1.6s linear infinite"}}>
          <defs>
            <linearGradient id="sweepGrad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor={C.cyan} stopOpacity="0"/>
              <stop offset="100%" stopColor={C.cyan} stopOpacity="0.55"/>
            </linearGradient>
          </defs>
          <path d="M24,24 L24,3 A21,21,0,0,1,44,24 Z" fill="url(#sweepGrad)"/>
          <line x1="24" y1="24" x2="24" y2="3" stroke={C.cyan} strokeWidth="1.2"/>
        </svg>
      )}
      <div style={{position:"absolute",inset:0,...s.cen}}>
        <div style={{width:5,height:5,borderRadius:"50%",background:C.cyan,animation:"pulse 1s ease-in-out infinite"}}/>
      </div>
    </div>
  );
}

function Toast({ toasts, dismiss }) {
  return (
    <div style={{position:"fixed",top:16,right:16,zIndex:999,...s.col,gap:8}}>
      {toasts.map(t => (
        <div key={t.id} className="anim-slide-r"
          style={{...s.row,gap:10,padding:"10px 14px",background:C.card2,
            border:`1px solid ${t.col}44`,borderRadius:8,boxShadow:`0 4px 20px rgba(0,0,0,0.4)`,
            minWidth:260,maxWidth:340}}>
          <t.Icon size={13} color={t.col} style={{flexShrink:0}}/>
          <span style={{fontSize:12,color:C.text,flex:1}}>{t.msg}</span>
          <button onClick={()=>dismiss(t.id)} style={{background:"none",border:"none",color:C.muted,cursor:"pointer",padding:0}}>
            <X size={12}/>
          </button>
        </div>
      ))}
    </div>
  );
}

function DashboardPanel({ networks: netsProp, devices: devsProp, diag, alertsProp = [], isLive = false }) {
  const nets=Array.isArray(netsProp)?netsProp:NETWORKS;
  const devs=Array.isArray(devsProp)?devsProp:DEVICES;
  const measuredNetworks=nets.filter(network=>network.rssi!=null&&Number.isFinite(Number(network.rssi)));
  const best=measuredNetworks.length?[...measuredNetworks].sort((a,b)=>Number(b.rssi)-Number(a.rssi))[0]:null;
  const onlineCount=devs.filter(device=>device.online===true).length;
  const offlineCount=devs.filter(device=>device.online===false).length;
  const unknownStatusCount=devs.length-onlineCount-offlineCount;
  const channelCountMap=nets.reduce((counts,network)=>{
    const channel=Number(network.ch);
    if(!Number.isInteger(channel)||channel<=0)return counts;
    const label=`${network.band||"Unknown"} · ${channel}`;
    counts[label]=(counts[label]||0)+1;
    return counts;
  },{});
  const channelCounts=Object.entries(channelCountMap).map(([label,count])=>({label,count}));
  return (
    <div style={{...s.col,gap:14}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        <Stat label="Networks Found" value={nets.length} sub={nets.some(n=>n.rogue===true)?`${nets.filter(n=>n.rogue===true).length} scanner candidate flag(s)`:"No scanner flags supplied"} col={C.cyan} Icon={Wifi} delay={1}/>
        <Stat label="Strongest RSSI" value={best?`${Number(best.rssi)} dBm`:"—"} sub={best?`${best.ssid||best.bssid} · ${best.band}`:"No measured RSSI in scan"} col={C.green} Icon={Signal} delay={2}/>
        <Stat label="Packet Loss" value={diag?.packet_loss_pct==null?"—":`${diag.packet_loss_pct}%`} sub={diag?.latency_ms==null?"No latency result":`Latency: ${diag.latency_ms} ms`} col={diag?.packet_loss_pct===0?C.green:C.yellow} Icon={Zap} delay={3}/>
        <Stat label="Device Status" value={`${onlineCount} confirmed online`} sub={`${offlineCount} offline · ${unknownStatusCount} unknown`} col={C.yellow} Icon={Smartphone} delay={4}/>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1.4fr 1fr",gap:10}}>
        <div className="hover-card anim-fade-d2" style={s.card}>
          <SHdr title={isLive?"Signal strength by observed BSS":"Signal chart preview"} sub={isLive?`${measuredNetworks.length} measured RSSI observations in current scan`:"Illustrative demo values; not live measurements"}/>
          <ResponsiveContainer width="100%" height={150}>
            <AreaChart data={measuredNetworks.map((network,index)=>({t:network.ssid||network.bssid||`BSS ${index+1}`,rssi:Number(network.rssi)}))} margin={{top:4,right:4,bottom:0,left:-20}}>
              <defs>
                <linearGradient id="gC" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={C.cyan}   stopOpacity={0.35}/>
                  <stop offset="95%" stopColor={C.cyan}   stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} vertical={false}/>
              <XAxis dataKey="t" hide/>
              <YAxis domain={[-75,-30]} tick={{fontSize:9,fill:C.muted}}/>
              <Tooltip contentStyle={{background:C.card2,border:`1px solid ${C.border}`,borderRadius:6,fontSize:11}}
                formatter={v=>[v.toFixed(1)+" dBm","RSSI"]}/>
              <Area type="monotone" dataKey="rssi" stroke={C.cyan} strokeWidth={2} fill="url(#gC)" dot={false} animationDuration={600}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="hover-card anim-fade-d3" style={s.card}>
          <SHdr title="Observed Alerts" right={<Tag text={`${alertsProp.length} ACTIVE`} col={C.yellow}/>}/>
          <div style={{...s.col,gap:7}}>
            {alertsProp.slice(0,4).map((a,i)=>{
              const col={danger:C.red,warning:C.yellow,success:C.green,info:C.cyan}[a.type];
              const I={danger:XCircle,warning:AlertTriangle,success:CheckCircle,info:Info}[a.type];
              return (
                <div key={i} style={{...s.row,gap:8,padding:"7px 9px",background:col+"11",
                  borderRadius:6,borderLeft:`2px solid ${col}`}}>
                  <I size={11} color={col} style={{flexShrink:0}}/>
                  <span style={{fontSize:11,color:C.textSec,lineHeight:1.35}}>{a.msg}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:10}}>
        <div className="hover-card anim-fade-d3" style={s.card}>
          <SHdr title="Nearby Networks" sub={`${nets.length} BSS records in the current view`}/>
          {(netsProp||NETWORKS).slice(0,4).map((n,i)=>(
            <div key={i} style={{...s.bet,padding:"7px 0",borderBottom:i<3?`1px solid ${C.border}44`:"none"}}>
              <div style={{...s.row,gap:7}}>
                {n.rogue&&<AlertTriangle size={11} color={C.red}/>}
                <span style={{fontSize:12,color:C.text,fontWeight:500}}>{n.ssid}</span>
                <Tag text={n.band} col={n.band==="6GHz"?C.purple:n.band==="5GHz"?C.cyan:C.yellow}/>
              </div>
              {n.rssi==null?<span style={{fontSize:10,color:C.muted}}>RSSI unavailable</span>:<AnimatedBars rssi={n.rssi}/>} 
            </div>
          ))}
        </div>
        <div className="hover-card anim-fade-d4" style={s.card}>
          <SHdr title={isLive?"Observed channel density":"Channel density preview"} sub={isLive?"Counts of BSS records per channel; airtime is not measured":"Illustrative example counts; not airtime utilisation"}/>
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={channelCounts} margin={{top:4,right:4,bottom:0,left:-24}}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} horizontal vertical={false}/>
              <XAxis dataKey="label" tick={{fontSize:9,fill:C.muted}}/>
              <YAxis allowDecimals={false} tick={{fontSize:9,fill:C.muted}}/>
              <Tooltip contentStyle={{background:C.card2,border:`1px solid ${C.border}`,borderRadius:6,fontSize:11}}
                formatter={v=>[v,"Observed BSS records"]}/>
              <Bar dataKey="count" fill={C.cyan} radius={[3,3,0,0]} opacity={0.82} animationDuration={800}/>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

function WirelessPanel({ networks: netsProp, isLive = false }) {
  const [filter,setFilter]=useState("");
  const [sort,setSort]=useState("rssi");
  const NETS = Array.isArray(netsProp) ? netsProp : NETWORKS;
  const nets=[...NETS]
    .filter(n=>(n.ssid||"").toLowerCase().includes(filter.toLowerCase())||(n.bssid||"").toLowerCase().includes(filter.toLowerCase()))
    .sort((a,b)=>sort==="rssi"?(Number(b.rssi??-Infinity)-Number(a.rssi??-Infinity)):sort==="snr"?(Number(b.snr??-Infinity)-Number(a.snr??-Infinity)):Number(a.ch??0)-Number(b.ch??0));
  const observedChannels=[...new Set(NETS.filter(n=>n.band&&Number(n.ch)>0).map(n=>`${n.band}:${Number(n.ch)}`))]
    .map(value=>{const [band,channel]=value.split(":");return {band,channel:Number(channel),count:NETS.filter(n=>n.band===band&&Number(n.ch)===Number(channel)).length};})
    .sort((a,b)=>a.count-b.count||a.band.localeCompare(b.band)||a.channel-b.channel);
  const leastObserved=observedChannels[0]||null;
  const measuredRssi=NETS.filter(n=>n.rssi!=null&&Number.isFinite(Number(n.rssi)));
  return (
    <div style={{...s.col,gap:14}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        <Stat label="BSS records" value={NETS.length} sub={`${NETS.filter(n=>n.band==="2.4GHz").length}×2.4 · ${NETS.filter(n=>n.band==="5GHz").length}×5 · ${NETS.filter(n=>n.band==="6GHz").length}×6 GHz`} col={C.cyan} Icon={Wifi} delay={1}/>
        <Stat label="Scanner flags" value={NETS.filter(n=>n.rogue===true).length} sub="Candidate metadata only; verify BSSIDs manually" col={C.yellow} Icon={Shield} delay={2}/>
        <Stat label="Least observed" value={leastObserved?`Ch ${leastObserved.channel} · ${leastObserved.band}`:"—"} sub={leastObserved?`${leastObserved.count} BSS observations; not airtime utilisation`:"No channel observations"} col={C.green} Icon={ScanLine} delay={3}/>
        <Stat label="Strongest" value={measuredRssi.length?`${Math.max(...measuredRssi.map(n=>Number(n.rssi)))} dBm`:"—"} sub={measuredRssi.length?([...measuredRssi].sort((a,b)=>Number(b.rssi)-Number(a.rssi))[0]?.ssid||"Observed BSS"):"No signal measurement"} col={C.purple} Icon={Rss} delay={4}/>
      </div>
      <div className="anim-fade-d2" style={s.card}>
        <div style={{...s.bet,marginBottom:12}}>
          <SHdr title={isLive?"Observed Wi-Fi scan":"Wi-Fi scan demo preview"} sub={isLive?`${nets.length} observed BSS records · local scanner`:`${nets.length} illustrative records · not live RF observations`}/>
          <div style={{...s.row,gap:8}}>
            <div style={{...s.row,gap:6,background:C.card2,border:`1px solid ${C.border}`,borderRadius:7,padding:"5px 10px"}}>
              <Search size={12} color={C.muted}/>
              <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filter..."
                style={{background:"none",border:"none",outline:"none",color:C.text,fontSize:12,width:100}}/>
            </div>
            <select value={sort} onChange={e=>setSort(e.target.value)}
              style={{background:C.card2,border:`1px solid ${C.border}`,borderRadius:7,padding:"5px 8px",color:C.textSec,fontSize:12}}>
              <option value="rssi">Sort: Signal</option>
              <option value="snr">Sort: SNR</option>
              <option value="ch">Sort: Channel</option>
            </select>
          </div>
        </div>
        <div style={{overflowX:"auto"}}>
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
            <thead>
              <tr style={{borderBottom:`1px solid ${C.border}`}}>
                {["SSID","BSSID","Band","Ch / Width","Security","Wi-Fi","RSSI","SNR","Clients","Vendor","Flags"].map(h=>(
                  <th key={h} style={{textAlign:"left",padding:"6px 10px",color:C.muted,fontWeight:600,whiteSpace:"nowrap",fontSize:10,letterSpacing:0.5}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {nets.map((n,i)=>(
                <tr key={i} className="hover-card"
                  style={{borderBottom:`1px solid ${C.border}22`,background:n.rogue?C.red+"08":"transparent",
                    animation:`fadeSlideIn 0.3s ${i*0.04}s ease both`}}>
                  <td style={{padding:"9px 10px",color:C.text,fontWeight:600}}>
                    <div style={{...s.row,gap:6}}>
                      {n.rogue&&<AlertTriangle size={10} color={C.red}/>}
                      {n.ssid}
                    </div>
                  </td>
                  <td style={{padding:"9px 10px",...s.mono,color:C.muted}}>{n.bssid}</td>
                  <td style={{padding:"9px 10px"}}><Tag text={n.band} col={n.band==="6GHz"?C.purple:n.band==="5GHz"?C.cyan:C.yellow}/></td>
                  <td style={{padding:"9px 10px",...s.mono,color:C.textSec}}>{n.ch} / {n.width}</td>
                  <td style={{padding:"9px 10px"}}><Tag text={n.sec} col={n.sec==="WPA3"?C.green:n.sec==="WPA2"?C.cyan:C.red}/></td>
                  <td style={{padding:"9px 10px"}}><Tag text={`Wi-Fi ${n.wifi}`} col={n.wifi==="6E"||n.wifi==="7"?C.purple:n.wifi==="6"?C.cyan:C.muted}/></td>
                  <td style={{padding:"9px 10px"}}>{n.rssi==null?<span style={{color:C.muted}}>—</span>:<AnimatedBars rssi={n.rssi}/>}</td>
                  <td style={{padding:"9px 10px",...s.mono,color:n.snr==null?C.muted:n.snr>30?C.green:n.snr>20?C.yellow:C.red}}>{n.snr==null?"—":`${n.snr} dB`}</td>
                  <td style={{padding:"9px 10px",color:C.textSec}}>{n.clients}</td>
                  <td style={{padding:"9px 10px",color:C.textSec}}>{n.vendor}</td>
                  <td style={{padding:"9px 10px"}}>
                    <div style={{...s.row,gap:4}}>
                      {n.rogue  && <Tag text="ROGUE" col={C.red}/>}
                      {n.sec==="Open" && <Tag text="OPEN" col={C.red}/>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div style={{...s.card,fontSize:11,color:C.muted}}>SSID similarity alone does not establish an Evil Twin. The observations above show nearby BSS records; they do not measure channel airtime utilisation or prove which channel is best. Verify BSSIDs and consult adapter/controller telemetry before taking action.</div>
    </div>
  );
}

function SignalPanel({ rssiData }) {
  const scores=[
    {label:"Signal Quality", val:null, col:C.green},
    {label:"Stability", val:null, col:C.cyan},
    {label:"Reliability", val:null, col:C.purple},
    {label:"Overall Health", val:null, col:C.green},
  ];
  return (
    <div style={{...s.col,gap:14}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        {scores.map((sc,i)=>(
          <div key={i} className={`hover-card anim-fade-d${i+1}`} style={s.card}>
            <div style={{fontSize:10,color:C.muted,marginBottom:8,letterSpacing:0.8,fontWeight:600}}>{sc.label.toUpperCase()}</div>
            <div style={{...s.row,gap:8,marginBottom:8}}>
              <span style={{fontSize:26,fontWeight:700,color:sc.col,animation:"countUp 0.5s ease both"}}>{sc.val==null?"—":sc.val}</span>
              <span style={{fontSize:12,color:C.muted}}>{sc.val==null?"not measured":"/100"}</span>
            </div>
            <div style={{height:4,background:C.border,borderRadius:2,overflow:"hidden"}}>
              <div style={{width:`${sc.val==null?0:sc.val}%`,height:"100%",background:sc.col,borderRadius:2,transition:"width 1.2s cubic-bezier(.4,0,.2,1)"}}/>
            </div>
          </div>
        ))}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
        <div className="hover-card anim-fade-d2" style={s.card}>
          <SHdr title="RSSI chart preview" sub="Illustrative samples; not measured from the current adapter"/>
          <ResponsiveContainer width="100%" height={170}>
            <AreaChart data={rssiData} margin={{top:4,right:4,bottom:0,left:-16}}>
              <defs>
                <linearGradient id="gR" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={C.cyan}   stopOpacity={0.4}/>
                  <stop offset="95%" stopColor={C.cyan}   stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} vertical={false}/>
              <XAxis dataKey="t" hide/>
              <YAxis domain={[-80,-30]} tick={{fontSize:9,fill:C.muted}}/>
              <Tooltip contentStyle={{background:C.card2,border:`1px solid ${C.border}`,borderRadius:6,fontSize:11}}
                formatter={v=>[v.toFixed(1)+" dBm","RSSI"]}/>
              <Area type="monotone" dataKey="rssi" stroke={C.cyan} strokeWidth={2} fill="url(#gR)" dot={false} animationDuration={800}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="hover-card anim-fade-d3" style={s.card}>
          <SHdr title="SNR chart preview" sub="Illustrative values; measured SNR requires a noise-floor reading"/>
          <ResponsiveContainer width="100%" height={170}>
            <AreaChart data={rssiData} margin={{top:4,right:4,bottom:0,left:-16}}>
              <defs>
                <linearGradient id="gS" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={C.purple} stopOpacity={0.4}/>
                  <stop offset="95%" stopColor={C.purple} stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} vertical={false}/>
              <XAxis dataKey="t" hide/>
              <YAxis domain={[20,55]} tick={{fontSize:9,fill:C.muted}}/>
              <Tooltip contentStyle={{background:C.card2,border:`1px solid ${C.border}`,borderRadius:6,fontSize:11}}
                formatter={v=>[v.toFixed(1)+" dB","SNR"]}/>
              <Area type="monotone" dataKey="snr" stroke={C.purple} strokeWidth={2} fill="url(#gS)" dot={false} animationDuration={800}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div className="anim-fade-d4" style={{...s.card,...s.row,gap:10}}>
        <div style={{...s.row,gap:8,padding:"9px 14px",background:C.greenFaint,border:`1px solid ${C.green}33`,borderRadius:7}}>
          <CheckCircle size={13} color={C.green}/>
          <span style={{fontSize:12,color:C.green}}>Stable — predicted -41 to -48 dBm next 10 samples</span>
        </div>
        <div style={{...s.row,gap:8,padding:"9px 14px",background:C.cyanFaint,border:`1px solid ${C.cyan}33`,borderRadius:7}}>
          <Info size={13} color={C.cyan}/>
          <span style={{fontSize:12,color:C.cyan}}>Roaming unlikely · Band steering: inactive</span>
        </div>
      </div>
    </div>
  );
}

function SpeedPanel({ speedData }) {
  const [running,setRunning]=useState(false);
  const [pct,setPct]=useState(0);
  const [phase,setPhase]=useState("idle");
  const [realDl,setRealDl]=useState(null);
  const [realUl,setRealUl]=useState(null);
  const [realPing,setRealPing]=useState(null);
  const [testError,setTestError]=useState("");
  const run=async()=>{
    if(running)return;
    setRunning(true);setPct(0);setPhase("testing");setTestError("");setRealDl(null);setRealUl(null);setRealPing(null);
    try{
      const r=await apiFetch(`${API_BASE}/api/speedtest`,{signal:AbortSignal.timeout(60000)});
      if(!r.ok)throw new Error(`Speed test returned HTTP ${r.status}`);
      const d=await r.json();
      if(d.error)throw new Error(d.error);
      const download=Number(d.download), upload=Number(d.upload), ping=Number(d.ping);
      if(![download,upload,ping].every(value=>Number.isFinite(value)&&value>=0))throw new Error("Speed test returned invalid measurements");
      setPct(100);setPhase("done");
      setRealDl(download);setRealUl(upload);setRealPing(ping);
    }catch(error){
      setPhase("error");setTestError(error.message||"Speed test failed");
    }
    setRunning(false);
  };
  const dlVal=phase==="done"&&realDl!=null?realDl:running?"…":"—";
  return (
    <div style={{...s.col,gap:14}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        <Stat label="Download" value={realDl==null?"—":`${realDl} Mbps`} sub="Latest completed test" col={C.cyan} Icon={ArrowDown} delay={1}/>
        <Stat label="Upload" value={realUl==null?"—":`${realUl} Mbps`} sub="Latest completed test" col={C.purple} Icon={ArrowUp} delay={2}/>
        <Stat label="Ping" value={realPing==null?"—":`${realPing} ms`} sub="Single reachability timing" col={C.green} Icon={Activity} delay={3}/>
        <Stat label="Bufferbloat" value="Not measured" sub="No loaded-latency test is run" col={C.muted} Icon={Gauge} delay={4}/>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1.5fr",gap:10}}>
        <div className="hover-card anim-fade-d2" style={{...s.card,...s.cen,flexDirection:"column",gap:18}}>
          <div style={{position:"relative",width:170,height:170}}>
            <svg width="170" height="170" viewBox="0 0 170 170">
              <circle cx="85" cy="85" r="76" fill="none" stroke={C.border} strokeWidth="8"/>
              <circle cx="85" cy="85" r="76" fill="none"
                stroke={phase==="upload"?C.purple:C.cyan} strokeWidth="8"
                strokeDasharray={`${2*Math.PI*76*(running?pct/100:1)} ${2*Math.PI*76}`}
                strokeLinecap="round" transform="rotate(-90 85 85)"
                style={{transition:"stroke-dasharray 0.06s linear,stroke 0.3s"}}/>
              {running&&[0.3,0.6].map((d,i)=>(
                <circle key={i} cx="85" cy="85" r="76" fill="none"
                  stroke={phase==="upload"?C.purple:C.cyan} strokeWidth="6" opacity="0.15"
                  style={{animation:`ripple 1.4s ${i*0.5}s ease-out infinite`}}/>
              ))}
            </svg>
            <div style={{position:"absolute",inset:0,...s.cen,flexDirection:"column"}}>
              <span style={{fontSize:36,fontWeight:700,color:phase==="upload"?C.purple:C.cyan,transition:"color 0.3s"}}>{dlVal}</span>
              <span style={{fontSize:12,color:C.muted}}>Mbps</span>
              <span style={{fontSize:10,color:C.textSec,marginTop:3,letterSpacing:0.5}}>
                {running?"TEST RUNNING":phase==="done"?"COMPLETE":phase==="error"?"FAILED":"READY"}
              </span>
            </div>
          </div>
          {testError&&<div role="alert" style={{...s.card,border:`1px solid ${C.red}55`,color:C.red,fontSize:12}}>{testError}</div>}
          <div style={{fontSize:10,color:C.muted,textAlign:"center"}}>This test contacts Cloudflare and transfers test data over the internet.</div>
          <button onClick={run} disabled={running}
            style={{padding:"10px 28px",background:running?C.border:C.cyan,
              color:running?C.muted:"#000",border:"none",borderRadius:8,
              fontWeight:700,cursor:running?"not-allowed":"pointer",fontSize:13,
              transition:"all 0.2s",animation:running?"glow 1s ease-in-out infinite":"none"}}>
            {running?"Testing...":phase==="error"?"Retry Speed Test":"▶ Run Speed Test"}
          </button>
        </div>
        <div className="hover-card anim-fade-d3" style={s.card}>
          <SHdr title="Speed chart preview" sub="Illustrative sample series; completed runs are not stored yet"/>
          <ResponsiveContainer width="100%" height={190}>
            <LineChart data={speedData} margin={{top:4,right:4,bottom:0,left:-16}}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} vertical={false}/>
              <XAxis dataKey="t" hide/>
              <YAxis domain={[300,1100]} tick={{fontSize:9,fill:C.muted}}/>
              <Tooltip contentStyle={{background:C.card2,border:`1px solid ${C.border}`,borderRadius:6,fontSize:11}}
                formatter={(v,n)=>[Math.round(v)+" Mbps",n==="dl"?"Download":"Upload"]}/>
              <Line type="monotone" dataKey="dl" stroke={C.cyan}   strokeWidth={2} dot={false} animationDuration={800}/>
              <Line type="monotone" dataKey="ul" stroke={C.purple} strokeWidth={2} dot={false} animationDuration={800}/>
            </LineChart>
          </ResponsiveContainer>
          <div style={{...s.row,gap:16,marginTop:8}}>
            {[["Download",C.cyan],["Upload",C.purple]].map(([l,c])=>(
              <div key={l} style={{...s.row,gap:5}}>
                <div style={{width:12,height:2,background:c,borderRadius:1}}/>
                <span style={{fontSize:11,color:C.textSec}}>{l}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function DevicesPanel({ devices: devsProp }) {
  const DEVS = Array.isArray(devsProp) ? devsProp : DEVICES;
  const onlineCount=DEVS.filter(device=>device.online===true).length;
  const offlineCount=DEVS.filter(device=>device.online===false).length;
  const unknownStatusCount=DEVS.length-onlineCount-offlineCount;
  const ICONS={Router:Server,Laptop:Monitor,Server:Database,Wearable:Eye,IoT:Rss,Unknown:AlertTriangle};
  const COLS ={Router:C.cyan,Laptop:C.blue,Server:C.purple,Wearable:C.green,IoT:C.yellow,Unknown:C.red};
  return (
    <div style={{...s.col,gap:14}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        <Stat label="Devices Found" value={DEVS.length} sub={`${onlineCount} online · ${offlineCount} offline · ${unknownStatusCount} unknown`} col={C.cyan} Icon={Smartphone} delay={1}/>
        <Stat label="Gateway"         value={DEVS.find(d=>d.gw)?.ip||"N/A"} sub={DEVS.find(d=>d.gw)?.vendor||""} col={C.purple} Icon={Activity} delay={2}/>
        <Stat label="Vendors Found"   value={[...new Set(DEVS.map(d=>d.vendor).filter(Boolean))].length} sub="Unique manufacturers" col={C.green} Icon={CheckCircle} delay={3}/>
        <Stat label="Unknown"         value={DEVS.filter(d=>!d.vendor||d.vendor==="???").length} sub="Unidentified MAC vendor" col={C.red} Icon={AlertTriangle} delay={4}/>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
        {DEVS.map((d,i)=>{
          const Icon=ICONS[d.type]||Smartphone;
          const col=COLS[d.type]||C.muted;
          return (
            <div key={i} className={`hover-card anim-fade-d${Math.min(i+1,5)}`}
              style={{...s.card,border:`1px solid ${d.type==="Unknown"?C.red+"44":C.border}`,
                background:d.type==="Unknown"?C.redFaint:C.card}}>
              <div style={{...s.bet,marginBottom:10}}>
                <div style={{...s.row,gap:9}}>
                  <div style={{...s.cen,width:36,height:36,borderRadius:8,background:col+"20"}}>
                    <Icon size={16} color={col}/>
                  </div>
                  <div>
                    <div style={{fontSize:13,fontWeight:600,color:C.text}}>{d.name}</div>
                    <div style={{fontSize:10,color:C.muted}}>{d.vendor}</div>
                  </div>
                </div>
                <div style={{...s.row,gap:5}}>
                  <PulseDot col={d.online===true?C.green:d.online===false?C.red:C.muted}/>
                  <span style={{fontSize:10,color:d.online===true?C.green:d.online===false?C.red:C.muted,fontWeight:600}}>{d.online===true?"Online":d.online===false?"Offline":"Status unknown"}</span>
                </div>
              </div>
              <div style={{...s.col,gap:5,padding:"8px 0",borderTop:`1px solid ${C.border}`}}>
                {[[ "IP",d.ip,true ],[ "MAC",d.mac,true ],[ "Bandwidth",d.bw==null?"—":d.bw+" Mbps",false ]].map(([k,v,mono])=>(
                  <div key={k} style={s.bet}>
                    <span style={{fontSize:10,color:C.muted}}>{k}</span>
                    <span style={{fontSize:11,...(mono?s.mono:{}),color:k==="Bandwidth"?C.cyan:C.textSec}}>{v}</span>
                  </div>
                ))}
                <div style={s.bet}>
                  <span style={{fontSize:10,color:C.muted}}>Signal</span>
                  {d.rssi==null?<span style={{fontSize:10,color:C.muted}}>—</span>:<AnimatedBars rssi={d.rssi}/>}
                </div>
                {d.gw&&<Tag text="GATEWAY" col={C.cyan}/>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function buildObservedAlerts(networks, diagnostics) {
  const alerts = [];
  for (const network of Array.isArray(networks) ? networks : []) {
    const label = network.ssid || network.bssid || "Unnamed access point";
    const security = String(network.sec ?? network.security ?? "").toLowerCase();
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
function AlertsPanel({ alerts = [] }) {
  const [filter,setFilter]=useState("all");
  const COLS={danger:C.red,warning:C.yellow,success:C.green,info:C.cyan};
  const ICONS={danger:XCircle,warning:AlertTriangle,success:CheckCircle,info:Info};
  const filtered=filter==="all"?alerts:alerts.filter(a=>a.type===filter);
  return (
    <div style={{...s.col,gap:14}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        <Stat label="Critical" value={alerts.filter(a=>a.type==="danger").length} sub="Verified critical conditions" col={C.red} Icon={XCircle} delay={1}/>
        <Stat label="Warnings" value={alerts.filter(a=>a.type==="warning").length} sub="From current measurements" col={C.yellow} Icon={AlertTriangle} delay={2}/>
        <Stat label="Info" value={alerts.filter(a=>a.type==="info").length} sub="Advisories" col={C.cyan} Icon={Info} delay={3}/>
        <Stat label="Resolved" value="—" sub="No alert history stored" col={C.green} Icon={CheckCircle} delay={4}/>
      </div>
      <div className="anim-fade-d2" style={s.card}>
        <div style={{...s.bet,marginBottom:12}}>
          <SHdr title="Alert Feed" sub="Real-time · last 24h"/>
          <div style={{...s.row,gap:5,flexWrap:"wrap"}}>
            {["all","danger","warning","info","success"].map(f=>(
              <button key={f} onClick={()=>setFilter(f)}
                style={{padding:"4px 10px",borderRadius:6,border:`1px solid ${filter===f?(COLS[f]||C.cyan):C.border}`,
                  background:filter===f?(COLS[f]?COLS[f]+"22":C.cyanFaint):"transparent",
                  color:filter===f?(COLS[f]||C.cyan):C.muted,fontSize:10,cursor:"pointer",
                  fontWeight:600,letterSpacing:0.4,textTransform:"capitalize",transition:"all 0.15s"}}>
                {f}
              </button>
            ))}
          </div>
        </div>
        <div style={{...s.col,gap:8}}>
          {filtered.length===0&&<div style={{padding:"16px 10px",color:C.muted,fontSize:12}}>No alert conditions were detected in the available measurements. This is not a guarantee that the network is secure.</div>}
          {filtered.map((a,i)=>{
            const c=COLS[a.type]; const I=ICONS[a.type];
            return (
              <div key={i} style={{...s.row,gap:12,padding:"11px 14px",
                background:c+"10",border:`1px solid ${c}22`,borderRadius:8,
                borderLeft:`3px solid ${c}`,animation:`fadeSlideIn 0.3s ${i*0.06}s ease both`}}>
                <I size={14} color={c} style={{flexShrink:0}}/>
                <span style={{flex:1,fontSize:12,color:C.text}}>{a.msg}</span>
                <span style={{fontSize:10,color:C.muted,flexShrink:0}}>{a.time}</span>
              </div>
            );
          })}
        </div>
      </div>
      <div style={{...s.card,fontSize:12,color:C.muted}}>Alert delivery is not connected in this build. Current alerts are displayed locally and are not sent to Discord, email or MQTT.</div>
    </div>
  );
}

function SystemPanel({ sysInfo }) {
  const cpu = sysInfo?.cpu_pct ?? null;
  const ram = sysInfo?.ram_pct ?? null;
  const temp = sysInfo?.cpu_temp ?? null;
  const disk = sysInfo?.disk_pct ?? null;
  const gauges=[
    {label:"CPU", val:cpu, col:C.cyan, unit:"%", detail:"Host processor utilisation"},
    {label:"RAM", val:ram, col:C.purple, unit:"%", detail:sysInfo?`${sysInfo.ram_used_gb??"—"} GB / ${sysInfo.ram_total_gb??"—"} GB`:"Unavailable"},
    {label:"Temp", val:temp, col:C.yellow, unit:"°C", detail:temp==null?"Temperature sensor unavailable":"Host-reported CPU temperature"},
    {label:"Disk", val:disk, col:C.green, unit:"%", detail:sysInfo?`${sysInfo.disk_used_gb??"—"} GB / ${sysInfo.disk_total_gb??"—"} GB`:"Unavailable"},
  ];
  return (
    <div style={{...s.col,gap:14}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10}}>
        {gauges.map((g,i)=>(
          <div key={i} className={`hover-card anim-fade-d${i+1}`} style={s.card}>
            <div style={{...s.bet,marginBottom:10}}>
              <span style={{fontSize:10,color:C.muted,letterSpacing:0.8,fontWeight:600}}>{g.label.toUpperCase()}</span>
              <span style={{fontSize:20,fontWeight:700,color:g.col}}>{g.val==null?"—":g.val}<span style={{fontSize:11,fontWeight:400}}>{g.val==null?"":g.unit}</span></span>
            </div>
            <div style={{height:5,background:C.border,borderRadius:3,overflow:"hidden"}}>
              <div style={{width:`${g.val==null?0:g.val}%`,height:"100%",background:g.col,borderRadius:3,transition:"width 1.2s cubic-bezier(.4,0,.2,1)"}}/>
            </div>
            <div style={{fontSize:10,color:C.muted,marginTop:5}}>{g.detail}</div>
          </div>
        ))}
      </div>
      <div className="anim-fade-d2" style={s.card}>
        <SHdr title="System Info" sub={sysInfo?`${sysInfo.os||"—"} · ${sysInfo.hostname||"—"}`:"Waiting for local host information"}/>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:14}}>
          {[
            ["OS", sysInfo?.os||"Unavailable"],
            ["CPU", sysInfo?.cpu_model||"Unavailable"],
            ["Memory", sysInfo?.ram_total_gb==null?"Unavailable":`${sysInfo.ram_total_gb} GB`],
            ["Disk", sysInfo?.disk_total_gb==null?"Unavailable":`${sysInfo.disk_total_gb} GB`],
            ["Uptime", sysInfo?.uptime||"Unavailable"],
            ["WiFi Adapter", sysInfo?.wifi_adapter||"Unavailable"],
          ].map(([k,v])=>(
            <div key={k}>
              <div style={{fontSize:10,color:C.muted,fontWeight:600,letterSpacing:0.5}}>{k.toUpperCase()}</div>
              <div style={{fontSize:12,color:C.textSec,marginTop:3,...s.mono}}>{v}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AiPanel({ networks: netsProp, devices: devsProp, diag, sysInfo, isLive = false }) {
  const nets = isLive ? (netsProp || []) : [];
  const devs = isLive ? (devsProp || []) : [];
  const measuredNets = nets.filter(n=>n.rssi!=null&&Number.isFinite(Number(n.rssi)));
  const best = measuredNets.length ? [...measuredNets].sort((a,b)=>Number(b.rssi)-Number(a.rssi))[0] : null;
  const rogues = nets.filter(n=>n.rogue===true);
  const loss = diag?.packet_loss_pct==null ? null : Number(diag.packet_loss_pct);
  const latency = diag?.latency_ms==null ? null : Number(diag.latency_ms);
  const hasDiagnosticMeasurements = loss!=null || latency!=null;
  const score = hasDiagnosticMeasurements ? Math.max(0, 100 - rogues.length*20 - (loss!=null&&loss>5?15:loss!=null&&loss>0?5:0) - (latency!=null&&latency>100?10:0)) : null;
  const liveInsights = isLive ? [
    rogues.length>0 && {Icon:Shield, col:C.yellow, title:"Scanner anomaly flag", body:`${rogues[0].ssid||"Unnamed network"} at ${rogues[0].bssid||"unknown BSSID"} was flagged by scan metadata. This is not proof of an Evil Twin; verify the BSSID against a trusted inventory.`},
    loss!=null && loss>5 && {Icon:Activity, col:C.yellow, title:"High Packet Loss", body:`${loss}% packet loss reported by the latest diagnostic. Possible causes include interference, distance, congestion or upstream loss.`},
    best && best.rssi > -50 && {Icon:Wifi, col:C.green, title:"Strong observed signal", body:`${best.ssid||best.bssid||"A nearby BSS"} measured ${best.rssi} dBm on ${best.band} in this scan. Throughput is not measured by RSSI alone.`},
    latency != null && latency > 100 && {Icon:Globe, col:C.yellow, title:"High Latency", body:`The latest diagnostic measured ${latency} ms latency. Check the route and repeat the test under comparable load.`},
    best && {Icon:ScanLine, col:C.cyan, title:"Strongest observed access point", body:`${best.ssid||best.bssid||"A nearby BSS"} is the strongest measured observation at ${best.rssi} dBm on ${best.band}. This scan alone cannot recommend a new channel.`},
    devs.filter(d=>!d.vendor||d.vendor==="???"||d.vendor==="Unknown vendor").length>0 && {Icon:Info, col:C.muted, title:"Vendor lookup unavailable", body:`${devs.filter(d=>!d.vendor||d.vendor==="???"||d.vendor==="Unknown vendor").length} neighbour record(s) have no resolved vendor. An unknown OUI is not evidence of a malicious device.`},
  ].filter(Boolean).slice(0,4) : [];
  const tips = liveInsights.length ? liveInsights : [
    {Icon:Info, col:C.cyan, title:"Awaiting live observations", body:"Connect the Wi-Fi Analyzer Pro local service to generate recommendations from measured scans and diagnostics. Demo samples are not security findings."},
  ];
  const summaryScore = isLive && hasDiagnosticMeasurements ? score : null;
  return (
    <div style={{...s.col,gap:14}}>
      <div className="anim-fade" style={{...s.card,background:C.purpleFaint,border:`1px solid ${C.purple}33`,animation:"borderPulse 3s ease-in-out infinite"}}>
        <div style={{...s.row,gap:10,marginBottom:10}}>
          <Bot size={18} color={C.purple}/>
          <span style={{fontSize:14,fontWeight:700,color:C.text}}>Network Health Summary · rules-based</span>
          <Tag text="v1.0.5 NEW" col={C.purple}/>
        </div>
        <p style={{fontSize:13,color:C.textSec,lineHeight:1.75,margin:0}}>
          Your network is <span style={{color:summaryScore==null?C.cyan:summaryScore>75?C.green:summaryScore>50?C.yellow:C.red,fontWeight:600}}>{summaryScore==null?"awaiting live observations":summaryScore>75?"generally healthy":summaryScore>50?"moderate":"needs attention"}</span>
          {rogues.length>0&&<span> with <span style={{color:C.red,fontWeight:600}}>{rogues.length} critical alert{rogues.length>1?"s":""}</span> requiring immediate action.</span>}
          {best&&<span> {best.ssid} ({best.band}) shows signal at {best.rssi} dBm{best.sec==="WPA3"?" with WPA3 — solid":best.sec==="WPA2"?" with WPA2":" (open — insecure)"}.</span>}
          {(latency!=null||loss!=null)&&<span> {latency!=null?`Measured latency: ${latency} ms.`:""} {loss!=null?`Measured packet loss: ${loss}%.`:""}</span>}
          {!isLive&&<span> Connect the backend for live AI analysis.</span>}
          {summaryScore==null?" A diagnostic score is unavailable until latency or packet loss is measured.":<> Diagnostic heuristic: <span style={{color:C.cyan,fontWeight:700}}>{summaryScore}/100</span> (not a security assessment).</>}
        </p>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:10}}>
        {tips.map((t,i)=>(
          <div key={i} className={`hover-card anim-fade-d${i+1}`}
            style={{...s.card,borderLeft:`3px solid ${t.col}`}}>
            <div style={{...s.row,gap:8,marginBottom:8}}>
              <t.Icon size={14} color={t.col}/>
              <span style={{fontSize:13,fontWeight:600,color:C.text}}>{t.title}</span>
            </div>
            <p style={{fontSize:12,color:C.textSec,lineHeight:1.65,margin:0}}>{t.body}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function FeatureGrid({ title, features, col=C.cyan }) {
  return (
    <div style={{...s.col,gap:14}}>
      <div className="anim-fade" style={{...s.card,border:`1px solid ${col}33`,background:col+"08"}}>
        <p style={{fontSize:11,color:C.muted,lineHeight:1.6,margin:"0 0 12px"}}>These are planned capability labels only. They are not active controls or completed integrations; use the Feature Workbench for the callable tools available in this build.</p>
        <div style={{...s.row,gap:10,marginBottom:14}}>
          <span style={{fontSize:15,fontWeight:700,color:col}}>{title}</span>
          <Tag text="CAPABILITY PREVIEW · NOT WIRED" col={C.muted}/>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8}}>
          {features.map((f,i)=>(
            <div key={i} className="hover-card"
              style={{...s.row,gap:8,padding:"8px 10px",background:C.card,borderRadius:7,
                border:`1px solid ${C.border}`,animation:`fadeSlideIn 0.3s ${i*0.025}s ease both`}}>
              <Info size={11} color={C.muted}/>
              <span style={{fontSize:11,color:C.textSec}}>{f}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

const NAV=[
  {g:"ANALYSIS", items:[
    {id:"dashboard",label:"Dashboard",     Icon:LayoutDashboard},
    {id:"wireless", label:"Wireless",      Icon:Wifi},
    {id:"signal",   label:"Signal",        Icon:Activity},
    {id:"phy",      label:"PHY Info",      Icon:Radio},
    {id:"interface",label:"Interfaces",    Icon:Layers},
  ]},
  {g:"NETWORK", items:[
    {id:"diagnostics",label:"Diagnostics", Icon:Globe},
    {id:"speed",      label:"Speed Test",  Icon:Zap},
    {id:"devices",    label:"Devices",     Icon:Smartphone},
    {id:"pcap",       label:"Packet Capture", Icon:FileSearch},
  ]},
  {g:"SYSTEM", items:[
    {id:"system",label:"System",           Icon:Monitor},
    {id:"router",label:"Router Support",   Icon:Server},
    {id:"agents",label:"Router Agents",    Icon:Shield},
  ]},
  {g:"INSIGHTS", items:[
    {id:"viz",    label:"Visualisation",   Icon:BarChart2},
    {id:"export", label:"Export",          Icon:Download},
    {id:"alerts", label:"Alerts",          Icon:Bell},
  ]},
  {g:"SMART", items:[
    {id:"ai",    label:"AI Features",      Icon:Bot},
    {id:"remote",label:"Remote",           Icon:Map},
  ]},
  {g:"ADVANCED", items:[
    {id:"advanced",label:"Advanced",       Icon:Wrench},
    {id:"api",     label:"API",            Icon:Code},
    {id:"featureTools", label:"Feature Workbench", Icon:Package},
  ]},
];

const PREFERENCE_KEY = "wifi-analyzer-pro.preferences";
const REFRESH_INTERVALS = [5, 10, 15, 30, 60];
const DEFAULT_PREFERENCES = {
  refreshIntervalSeconds: 10,
  compactSidebar: false,
  hideDemoData: false,
  reducedMotion: false,
};

function loadPreferences() {
  try {
    const stored = JSON.parse(window.localStorage.getItem(PREFERENCE_KEY) || "{}");
    return {
      refreshIntervalSeconds: REFRESH_INTERVALS.includes(stored.refreshIntervalSeconds)
        ? stored.refreshIntervalSeconds : DEFAULT_PREFERENCES.refreshIntervalSeconds,
      compactSidebar: stored.compactSidebar === true,
      hideDemoData: stored.hideDemoData === true,
      reducedMotion: stored.reducedMotion === true,
    };
  } catch {
    return { ...DEFAULT_PREFERENCES };
  }
}

function SettingsOverlay({ preferences, onChange, onClose }) {
  const labelStyle = { fontSize: 12, color: C.text, fontWeight: 600 };
  const hintStyle = { fontSize: 10, color: C.muted, marginTop: 3 };
  const controlStyle = {
    background: C.bg, color: C.text, border: `1px solid ${C.border}`,
    borderRadius: 7, padding: "7px 9px", fontSize: 12,
  };
  return (
    <div role="presentation" onMouseDown={event => {
      if (event.target === event.currentTarget) onClose();
    }} style={{
      position: "fixed", inset: 0, zIndex: 1000, background: "rgba(2,6,14,.78)",
      display: "flex", alignItems: "center", justifyContent: "center", padding: 18,
      backdropFilter: "blur(5px)",
    }}>
      <section role="dialog" aria-modal="true" aria-labelledby="settings-title"
        style={{
          width: "min(480px, 100%)", maxHeight: "min(680px, 90vh)", overflowY: "auto",
          background: C.card, border: `1px solid ${C.borderHov}`, borderRadius: 14,
          boxShadow: "0 24px 80px rgba(0,0,0,.5)", padding: 20,
        }}>
        <div style={{ ...s.bet, marginBottom: 5 }}>
          <div style={{ ...s.row, gap: 10 }}>
            <div style={{
              width: 34, height: 34, borderRadius: 9, background: C.cyanFaint,
              display: "grid", placeItems: "center", border: `1px solid ${C.cyan}33`,
            }}><Settings size={16} color={C.cyan}/></div>
            <div>
              <div id="settings-title" style={{ fontSize: 15, fontWeight: 750, color: C.text }}>Signal Pulse settings</div>
              <div style={{ fontSize: 10, color: C.muted }}>Local dashboard behaviour and accessibility</div>
            </div>
          </div>
          <button type="button" onClick={onClose} aria-label="Close settings"
            style={{ ...controlStyle, width: 32, height: 32, padding: 0, cursor: "pointer" }}>
            <X size={14}/>
          </button>
        </div>

        <div style={{ display: "grid", gap: 1, marginTop: 18 }}>
          <div style={{ ...s.bet, padding: "12px 0", borderBottom: `1px solid ${C.border}` }}>
            <div>
              <div style={labelStyle}>Automatic refresh</div>
              <div style={hintStyle}>Refresh local observations in the background</div>
            </div>
            <select aria-label="Automatic refresh interval"
              value={preferences.refreshIntervalSeconds}
              onChange={event => onChange({ refreshIntervalSeconds: Number(event.target.value) })}
              style={controlStyle}>
              {REFRESH_INTERVALS.map(seconds => <option key={seconds} value={seconds}>{seconds} seconds</option>)}
            </select>
          </div>

          <label style={{ ...s.bet, padding: "12px 0", borderBottom: `1px solid ${C.border}`, cursor: "pointer" }}>
            <span>
              <span style={labelStyle}>Compact sidebar</span>
              <span style={{ ...hintStyle, display: "block" }}>Keep navigation collapsed between sessions</span>
            </span>
            <input type="checkbox" checked={preferences.compactSidebar}
              onChange={event => onChange({ compactSidebar: event.target.checked })}
              aria-label="Compact sidebar" style={{ width: 16, height: 16, accentColor: C.cyan }}/>
          </label>

          <label style={{ ...s.bet, padding: "12px 0", borderBottom: `1px solid ${C.border}`, cursor: "pointer" }}>
            <span>
              <span style={labelStyle}>Hide demo observations</span>
              <span style={{ ...hintStyle, display: "block" }}>Do not show example networks or devices when live data is unavailable</span>
            </span>
            <input type="checkbox" checked={preferences.hideDemoData}
              onChange={event => onChange({ hideDemoData: event.target.checked })}
              aria-label="Hide demo observations" style={{ width: 16, height: 16, accentColor: C.cyan }}/>
          </label>

          <label style={{ ...s.bet, padding: "12px 0", cursor: "pointer" }}>
            <span>
              <span style={labelStyle}>Reduce motion</span>
              <span style={{ ...hintStyle, display: "block" }}>Reduce animated transitions and visual effects</span>
            </span>
            <input type="checkbox" checked={preferences.reducedMotion}
              onChange={event => onChange({ reducedMotion: event.target.checked })}
              aria-label="Reduce motion" style={{ width: 16, height: 16, accentColor: C.cyan }}/>
          </label>
        </div>

        <div style={{
          marginTop: 14, padding: 11, borderRadius: 8, background: C.card2,
          border: `1px solid ${C.border}`, fontSize: 10, lineHeight: 1.6, color: C.textSec,
        }}>
          <Shield size={12} color={C.green} style={{ verticalAlign: "middle", marginRight: 6 }}/>
          Preferences are stored in this browser only. Network observations remain on the local analyzer unless you configure an external integration.
        </div>
      </section>
    </div>
  );
}

export default function App() {
  const { logout } = useAuth();
  const [tab,setTab]=useState("dashboard");
  const [scanning,setScanning]=useState(false);
  const [preferences,setPreferences]=useState(loadPreferences);
  const [settingsOpen,setSettingsOpen]=useState(false);
  const collapsed=preferences.compactSidebar;
  const [toasts,setToasts]=useState([]);
  const [rssiData]=useState(genRSSI);
  const [speedData]=useState(genSpeed);
  const [liveMode,setLiveMode]=useState(false);
  const [liveNets,setLiveNets]=useState(null);
  const [liveDevs,setLiveDevs]=useState(null);
  const [liveSystem,setLiveSystem]=useState(null);
  const [liveDiag,setLiveDiag]=useState(null);
  const [checking,setChecking]=useState(true);

  useEffect(()=>{
    try {
      window.localStorage.setItem(PREFERENCE_KEY, JSON.stringify(preferences));
    } catch {
      // Keep the active session usable when browser storage is unavailable.
    }
  },[preferences]);

  useEffect(()=>{
    let disposed=false;
    const refreshLiveData=async()=>{
      try{
        const hasResponse=await apiFetch(`${API_BASE}/api/has_wifi`,{signal:AbortSignal.timeout(4000)});
        if(!hasResponse.ok)throw new Error(`Wi-Fi probe returned HTTP ${hasResponse.status}`);
        const availability=await hasResponse.json();
        if(!availability.has_wifi){
          if(!disposed)setLiveMode(false);
          return;
        }
        const responses=await Promise.all([
          apiFetch(`${API_BASE}/api/scan`,{signal:AbortSignal.timeout(15000)}),
          apiFetch(`${API_BASE}/api/devices`,{signal:AbortSignal.timeout(10000)}),
          apiFetch(`${API_BASE}/api/system`,{signal:AbortSignal.timeout(5000)}),
          apiFetch(`${API_BASE}/api/diagnostics`,{signal:AbortSignal.timeout(18000)}),
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
    const intervalId=setInterval(refreshLiveData,preferences.refreshIntervalSeconds*1000);
    return()=>{disposed=true;clearInterval(intervalId);};
  },[preferences.refreshIntervalSeconds]);

  const networks=liveMode&&Array.isArray(liveNets)
    ?liveNets.map(toUiNetwork)
    :preferences.hideDemoData?[]:(Array.isArray(liveNets)?liveNets.map(toUiNetwork):NETWORKS);
  const devices=liveMode&&Array.isArray(liveDevs)
    ?liveDevs.map(toUiDevice)
    :preferences.hideDemoData?[]:(Array.isArray(liveDevs)?liveDevs.map(toUiDevice):DEVICES);
  const observedAlerts=liveMode?buildObservedAlerts(networks,liveDiag):[];

  const addToast=(msg,type="info")=>{
    const id=Date.now();
    const COLS={danger:C.red,warning:C.yellow,success:C.green,info:C.cyan};
    const ICONS={danger:XCircle,warning:AlertTriangle,success:CheckCircle,info:Info};
    setToasts(t=>[...t,{id,msg,col:COLS[type],Icon:ICONS[type]}]);
    setTimeout(()=>setToasts(t=>t.filter(x=>x.id!==id)),3800);
  };

  const dismissToast=id=>setToasts(t=>t.filter(x=>x.id!==id));

  const scan=async()=>{
    if(scanning)return;
    setScanning(true);
    try{
      const response=await apiFetch(`${API_BASE}/api/scan`,{signal:AbortSignal.timeout(18000)});
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

  const switchTab=id=>{
    setTab(id);

  };

  const panels={
    featureTools: <FeatureWorkbench/>,
    pcap:         <PcapAnalyzer/>,
    agents:       <RouterAgentConsole/>,
    dashboard:   <DashboardPanel networks={networks} devices={devices} diag={liveDiag} alertsProp={observedAlerts} isLive={liveMode}/>,
    wireless:    <WirelessPanel networks={networks} isLive={liveMode}/>,
    signal:      <SignalPanel rssiData={rssiData}/>,
    speed:       <SpeedPanel speedData={speedData}/>,
    devices:     <DevicesPanel devices={devices}/>,
    alerts:      <AlertsPanel alerts={observedAlerts}/>,
    system:      <SystemPanel sysInfo={liveSystem}/>,
    ai:          <AiPanel networks={networks} devices={devices} diag={liveDiag} sysInfo={liveSystem} isLive={liveMode}/>,
    phy:         <FeatureGrid title="PHY Information" badge="v1.0.5" col={C.cyan}
      features={["MCS index display","NSS spatial streams","Channel width","Short guard interval","Bitrate TX/RX","TX power (dBm)","RX sensitivity","PHY type (HT/VHT/HE/EHT)","Antenna chains","Radio capabilities","Regulatory domain","Max EIRP"]} />,
    interface:   <FeatureGrid title="Interface Monitor" badge="v1.0.5" col={C.purple}
      features={["RX packet counter","TX packet counter","RX error counter","TX error counter","RX drop counter","TX drop counter","Retry counter","Collision stats","Per-interface throughput","Live graph","Multi-interface","Auto-refresh"]} />,
    diagnostics: <FeatureGrid title="Network Diagnostics" badge="v1.0.5" col={C.green}
      features={["Gateway latency","Internet latency","DNS lookup timing","Packet loss %","MTU path discovery","Traceroute","Route visualisation","IPv4 analysis","IPv6 analysis","DNS benchmarking","Gateway health","Bufferbloat test"]} />,
    router:      <FeatureGrid title="Router Support" badge="v1.0.5" col={C.blue}
      features={["OpenWrt LuCI API","DD-WRT SSH","pfSense XML-RPC","OPNsense API","UniFi Controller","MikroTik RouterOS","TP-Link Omada","ASUSWRT-Merlin","GL.iNet API","Tomato","Real-time stats pull","Config backup"]} />,
    viz:         <FeatureGrid title="Visualisation" badge="v1.0.5" col={C.yellow}
      features={["Live dashboard","Channel heatmap","Signal coverage map","Timeline graphs","Interactive charts","Topology graph","Device relationship","Geographic maps","Frequency spectrum","Band utilisation","Client density","Animation everywhere"]} />,
    export:      <FeatureGrid title="Export & Reports" badge="v1.0.5" col={C.green}
      features={["CSV export","JSON export","PDF reports (ReportLab)","HTML reports","Scheduled reports","Email delivery","Screenshot export","Config backup","Session history","Grafana dashboard","Prometheus metrics","Plugin SDK"]} />,
    remote:      <FeatureGrid title="Remote Monitoring" badge="v1.0.5" col={C.blue}
      features={["Multi-site dashboard","Pi agent (headless)","Remote web UI","API key auth","Role-based access","Cloud sync optional","Self-hosted mode","VPN-safe tunnel","Site comparison","Centralized alerts","Agent auto-update","WebSocket push"]} />,
    advanced:    <FeatureGrid title="Advanced Networking" badge="v1.0.5" col={C.yellow}
      features={["Wake-on-LAN","ARP table viewer","DHCP lease table","DNS cache viewer","TCP connectivity test","UDP test","Service detection","SSL cert expiry","Port scanner","nftables viewer","VLAN analysis","Interface config"]} />,
    api:         <FeatureGrid title="API & Integrations" badge="v1.0.5" col={C.cyan}
      features={["REST API (OpenAPI 3.0)","Interactive docs /docs","WebSocket ws/live","Prometheus /metrics","Grafana dashboard JSON","Home Assistant MQTT","Node-RED templates","Webhooks","Plugin SDK","Mobile app API","OAuth2 auth","Rate limiting"]} />,
  };

  const allItems=NAV.flatMap(g=>g.items);
  const current=allItems.find(n=>n.id===tab);

  return (
    <div style={{display:"flex",height:"100vh",background:C.bg,color:C.text,fontFamily:"system-ui,-apple-system,sans-serif",overflow:"hidden"}}>
      <style>{ANIM}{preferences.reducedMotion?`
        *,*::before,*::after {
          animation-duration: 0.001ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0.001ms !important;
          scroll-behavior: auto !important;
        }
      `:""}</style>
      <Toast toasts={toasts} dismiss={dismissToast}/>
      {settingsOpen&&<SettingsOverlay preferences={preferences}
        onChange={updates=>setPreferences(current=>({...current,...updates}))}
        onClose={()=>setSettingsOpen(false)}/>}

      <aside style={{width:collapsed?54:210,flexShrink:0,background:C.card,
        borderRight:`1px solid ${C.border}`,display:"flex",flexDirection:"column",
        transition:"width 0.25s cubic-bezier(.4,0,.2,1)",overflow:"hidden"}}>
        <div style={{padding:"12px 10px",borderBottom:`1px solid ${C.border}`,
          display:"flex",alignItems:"center",gap:10,height:54,flexShrink:0}}>
          <div style={{width:30,height:30,borderRadius:8,background:C.cyanFaint,
            display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,
            border:`1px solid ${C.cyan}33`,animation:"glow 3s ease-in-out infinite"}}>
            <svg width="19" height="19" viewBox="0 0 24 24" fill="none"
              stroke={C.cyan} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
              aria-hidden="true">
              <path d="M3 8.5a14 14 0 0 1 18 0M6.4 11.8a8.8 8.8 0 0 1 11.2 0"/>
              <path d="M2.8 17h4.1l2-4 3.1 7 2.5-5h6.7"/>
            </svg>
          </div>
          {!collapsed&&(
            <div>
              <div style={{fontSize:12,fontWeight:700,color:C.text,lineHeight:1,whiteSpace:"nowrap"}}>WiFi Analyzer</div>
              <div style={{fontSize:9,color:C.cyan,fontWeight:700,letterSpacing:0.8}}>SIGNAL PULSE · PRO v1.0.7</div>
            </div>
          )}
        </div>

        <div style={{flex:1,overflowY:"auto",padding:"6px 0"}}>
          {NAV.map(group=>(
            <div key={group.g}>
              {!collapsed&&(
                <div style={{fontSize:8,color:C.muted,letterSpacing:1.2,padding:"8px 12px 3px",
                  fontWeight:700,userSelect:"none"}}>{group.g}</div>
              )}
              {group.items.map(item=>{
                const active=tab===item.id;
                return (
                  <button key={item.id}
                    className={`nav-btn${active?" active":""}`}
                    onClick={()=>switchTab(item.id)}
                    title={collapsed?item.label:undefined}
                    style={{width:"100%",display:"flex",alignItems:"center",gap:9,
                      padding:collapsed?"9px 0":"7px 12px",
                      paddingLeft:collapsed?0:14,justifyContent:collapsed?"center":"flex-start",
                      background:active?C.cyanFaint:"transparent",
                      borderLeft:`2px solid ${active?C.cyan:"transparent"}`,
                      border:"none",borderLeftWidth:2,
                      cursor:"pointer",color:active?C.cyan:C.muted,
                      fontSize:12,fontWeight:active?600:400,textAlign:"left",
                      transition:"all 0.15s"}}>
                    <item.Icon size={14} style={{flexShrink:0}}/>
                    {!collapsed&&<span style={{whiteSpace:"nowrap"}}>{item.label}</span>}
                  </button>
                );
              })}
            </div>
          ))}
        </div>

        <div style={{padding:"8px 8px",borderTop:`1px solid ${C.border}`}}>
          <button onClick={()=>setPreferences(current=>({...current,compactSidebar:!current.compactSidebar}))}
            style={{width:"100%",padding:"7px",background:C.card2,
              border:`1px solid ${C.border}`,borderRadius:7,
              color:C.muted,cursor:"pointer",fontSize:11,display:"flex",
              alignItems:"center",justifyContent:"center",gap:6,transition:"all 0.2s"}}>
            <Menu size={13}/>
            {!collapsed&&<span>Collapse</span>}
          </button>
        </div>
      </aside>

      <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
        <header style={{padding:"0 18px",borderBottom:`1px solid ${C.border}`,
          background:C.card,display:"flex",alignItems:"center",
          justifyContent:"space-between",height:54,flexShrink:0}}>
          <div style={{display:"flex",alignItems:"center",gap:12}}>
            <RadarWidget scanning={scanning}/>
            <div>
              <div style={{fontSize:14,fontWeight:700,color:C.text}}>{current?.label||"Dashboard"}</div>
              <div style={{fontSize:10,color:C.muted,display:"flex",alignItems:"center",gap:5}}>
                <PulseDot col={C.green} size={6}/>
                <span>{liveMode ? `LIVE · ${liveSystem?.wifi_interface || "Wi-Fi adapter detected"}` : "DEMO DATA · no live adapter connected"}</span>
              </div>
            </div>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <div style={{display:"flex",alignItems:"center",gap:6,fontSize:11,color:C.textSec,
              padding:"4px 10px",background:C.card2,border:`1px solid ${C.border}`,borderRadius:6}}>
              <Signal size={11} color={C.cyan}/>
              <span style={{fontFamily:"monospace"}}>{liveSystem?.wifi_interface||"No connected interface reported"}</span>
            </div>
            {!checking && (
              <div style={{display:"flex",alignItems:"center",gap:5,fontSize:10,fontWeight:700,
                padding:"3px 9px",borderRadius:5,letterSpacing:0.6,
                background:liveMode?"rgba(34,197,94,0.12)":"rgba(168,85,247,0.12)",
                border:`1px solid ${liveMode?C.green+"44":C.purple+"44"}`,
                color:liveMode?C.green:C.purple}}>
                <span style={{width:5,height:5,borderRadius:"50%",
                  background:liveMode?C.green:C.purple,
                  animation:"pulse 1.4s ease-in-out infinite",display:"inline-block"}}/>
                {liveMode?"LIVE":"DEMO"}
              </div>
            )}
            <button onClick={scan} disabled={scanning}
              style={{display:"flex",alignItems:"center",gap:6,padding:"6px 14px",
                background:scanning?C.cyanFaint:C.cyan+"22",
                border:`1px solid ${C.cyan}55`,borderRadius:7,
                color:C.cyan,cursor:scanning?"not-allowed":"pointer",
                fontSize:12,fontWeight:600,transition:"all 0.2s"}}>
              <RefreshCw size={12} style={{animation:scanning?"spin 0.7s linear infinite":"none"}}/>
              {scanning?"Scanning...":"Scan Now"}
            </button>
            <button onClick={logout} title="Sign out" aria-label="Sign out"
              style={{width:32,height:32,display:"flex",alignItems:"center",justifyContent:"center",
                background:C.card2,border:`1px solid ${C.border}`,borderRadius:7,
                cursor:"pointer",color:C.muted,transition:"all 0.15s"}}>
              <Lock size={14}/>
            </button>
            <button onClick={()=>setSettingsOpen(true)} aria-label="Open settings" title="Settings"
              style={{width:32,height:32,display:"flex",alignItems:"center",justifyContent:"center",
                background:C.card2,border:`1px solid ${C.border}`,borderRadius:7,
                cursor:"pointer",color:C.muted,transition:"all 0.15s"}}>
              <Settings size={14}/>
            </button>
          </div>
        </header>

        <main style={{flex:1,overflowY:"auto",padding:14}}>
          <div key={tab} style={{animation:"fadeSlideIn 0.28s ease both"}}>
            {panels[tab]||<div style={{color:C.muted,display:"flex",alignItems:"center",justifyContent:"center",height:"60vh"}}>Coming soon</div>}
          </div>
        </main>
      </div>
    </div>
  );
}
