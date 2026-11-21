#!/usr/bin/env python3
"""
WiFi Analyzer Pro - All-in-one server
Serves the dashboard UI + API on port 199.
Run:  sudo python3 server.py
Then open:  http://<pi-ip>:199
"""

import sys, os, json, platform, subprocess, re, time, mimetypes
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime, timezone

# Runtime dependencies must be installed by the installer or bundled by PyInstaller.
# Never mutate the user's Python environment when the application starts.
import psutil

if __package__:
    from .auth import AuthManager, MFARequiredError
    from .billing import (
        PLAN_CATALOG, StripeApiError, StripeSignatureError, WorkspaceBillingStore,
        configured_price_plans, create_billing_portal_session, create_checkout_session,
        verify_stripe_signature,
    )
    from .audit_store import SecurityAuditStore
    from .audit_checkpoint import create_signed_checkpoint
    from .live_capture import LiveCaptureManager
    from .report_worker import _PinnedHTTPSConnection, _resolve_public_addresses
    from .webhook_delivery_store import (
        WebhookDeliveryConflictError, WebhookDeliveryNotFoundError, WebhookDeliveryStore,
    )
    from .webhook_subscription_store import (
        WebhookSubscriptionConflictError, WebhookSubscriptionNotFoundError, WebhookSubscriptionStore,
    )
    from .rate_limit import TokenBucketRateLimiter, DEFAULT_POLICIES
    from .feature_plugins import catalog as feature_catalog, run as run_feature
    from .site_history import DuplicateSnapshotError, SiteHistoryStore
    from .router_adapters.registry import list_manifests as router_adapter_manifests
    from .router_adapters.health_store import (
        AgentAuthenticationError,
        AgentCredentialConflictError,
        DuplicateAgentDeliveryError,
        DuplicateAgentSnapshotError,
        RouterAgentHealthStore,
    )
    from .router_adapters.report_job_store import (
        ReportJobConflictError,
        ReportJobNotFoundError,
        RouterReportJobStore,
    )
else:  # Direct execution: python wifi_analyzer_backend/server.py
    from auth import AuthManager, MFARequiredError
    from billing import (
        PLAN_CATALOG, StripeApiError, StripeSignatureError, WorkspaceBillingStore,
        configured_price_plans, create_billing_portal_session, create_checkout_session,
        verify_stripe_signature,
    )
    from audit_store import SecurityAuditStore
    from audit_checkpoint import create_signed_checkpoint
    from live_capture import LiveCaptureManager
    from report_worker import _PinnedHTTPSConnection, _resolve_public_addresses
    from webhook_delivery_store import (
        WebhookDeliveryConflictError, WebhookDeliveryNotFoundError, WebhookDeliveryStore,
    )
    from webhook_subscription_store import (
        WebhookSubscriptionConflictError, WebhookSubscriptionNotFoundError, WebhookSubscriptionStore,
    )
    from rate_limit import TokenBucketRateLimiter, DEFAULT_POLICIES
    from feature_plugins import catalog as feature_catalog, run as run_feature
    from site_history import DuplicateSnapshotError, SiteHistoryStore
    from router_adapters.registry import list_manifests as router_adapter_manifests
    from router_adapters.health_store import (
        AgentAuthenticationError,
        AgentCredentialConflictError,
        DuplicateAgentSnapshotError,
        RouterAgentHealthStore,
    )
    from router_adapters.report_job_store import (
        ReportJobConflictError,
        ReportJobNotFoundError,
        RouterReportJobStore,
    )

OS = platform.system()
APP_VERSION = "1.0.7"
DEMO_MODE = os.getenv("WIFI_ANALYZER_DEMO", "").strip().lower() in {"1", "true", "yes", "on"}
DEFAULT_CORS_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}
CORS_ORIGINS = {
    origin.strip()
    for origin in os.getenv("WIFI_ANALYZER_CORS_ORIGINS", "").split(",")
    if origin.strip()
} or DEFAULT_CORS_ORIGINS

AUTH = AuthManager()
HISTORY = SiteHistoryStore()
AGENT_HEALTH = RouterAgentHealthStore()
REPORT_JOBS = RouterReportJobStore()
AUDIT = SecurityAuditStore()
LIVE_CAPTURE = LiveCaptureManager()
WEBHOOK_DELIVERIES = WebhookDeliveryStore()
WEBHOOK_SUBSCRIPTIONS = WebhookSubscriptionStore()
BILLING = WorkspaceBillingStore()
BILLING_QUOTA_LOCK = __import__("threading").RLock()
RATE_LIMITER = TokenBucketRateLimiter()
RATE_LIMIT_POLICIES = dict(DEFAULT_POLICIES)

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_wifi_iface():
    if OS == "Linux":
        try:
            out = subprocess.check_output(["iw","dev"], stderr=subprocess.DEVNULL).decode()
            m = re.search(r"Interface (\w+)", out)
            if m: return m.group(1)
        except: pass
        try:
            for iface in os.listdir("/sys/class/net"):
                if os.path.exists(f"/sys/class/net/{iface}/wireless"):
                    return iface
        except: pass
    elif OS == "Darwin":
        return "en0"
    return None

def freq_to_ch(f):
    """Map an IEEE 802.11 centre frequency in MHz to its primary channel."""
    f = int(round(float(f)))
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 5180 <= f <= 5885:
        return (f - 5000) // 5
    if 5955 <= f <= 7115:
        return (f - 5950) // 5
    return 0


def ch_to_freq(ch):
    ch = int(ch)
    if ch == 14:
        return 2484
    if 1 <= ch <= 13:
        return 2407 + ch * 5
    if 32 <= ch <= 177:
        return 5000 + ch * 5
    return 0


def frequency_band(frequency_mhz):
    if frequency_mhz >= 5925:
        return "6GHz"
    if frequency_mhz >= 4900:
        return "5GHz"
    return "2.4GHz"


def security_from_ies(text):
    upper = text.upper()
    if "SAE" in upper and "PSK" in upper:
        return "WPA2/WPA3"
    if "SAE" in upper or "WPA3" in upper:
        return "WPA3"
    if "WPA2" in upper or "RSN:" in upper:
        return "WPA2"
    if "WPA:" in upper or re.search(r"WPA", upper):
        return "WPA"
    if "PRIVACY" in upper or "ENCRYPTION KEY:ON" in upper:
        return "WEP"
    return "Open"

def rssi_quality(rssi):
    if rssi>=-50: return 100
    if rssi<=-100: return 0
    return int(2*(rssi+100))

def link_speed(rssi, band):
    if band=="5GHz":
        for r,s in [(-50,867),(-60,433),(-70,216),(-80,72)]: 
            if rssi>=r: return s
        return 24
    else:
        for r,s in [(-50,300),(-60,150),(-70,72),(-80,36)]:
            if rssi>=r: return s
        return 11

def enrich(net):
    """Calculate signal-to-noise only when a real noise measurement exists."""
    net["quality"] = rssi_quality(net["rssi"])
    if net.get("noise") is not None:
        net["snr"] = net["rssi"] - net["noise"]
    return net

# ── Scan ──────────────────────────────────────────────────────────────────────
def mock_networks():
    import random; random.seed(int(time.time())//10)
    nets = [
        {"ssid":"HomeNetwork_5G","bssid":"AA:BB:CC:DD:EE:01","rssi":random.randint(-55,-45),"channel":36,"band":"5GHz"},
        {"ssid":"HomeNetwork_2G","bssid":"AA:BB:CC:DD:EE:02","rssi":random.randint(-60,-50),"channel":6,"band":"2.4GHz"},
        {"ssid":"Neighbor_WiFi","bssid":"AA:BB:CC:DD:EE:03","rssi":random.randint(-75,-65),"channel":11,"band":"2.4GHz"},
        {"ssid":"Office_Net","bssid":"AA:BB:CC:DD:EE:04","rssi":random.randint(-80,-70),"channel":48,"band":"5GHz"},
        {"ssid":"GuestNet","bssid":"AA:BB:CC:DD:EE:05","rssi":random.randint(-85,-75),"channel":1,"band":"2.4GHz"},
        {"ssid":"Corp_Secure","bssid":"AA:BB:CC:DD:EE:06","rssi":random.randint(-70,-60),"channel":100,"band":"5GHz"},
    ]
    result = []
    for n in nets:
        n["frequency"] = round(ch_to_freq(n["channel"])/1000,3)
        n["security"] = random.choice(["WPA2","WPA3","WPA2/WPA3","Open"])
        n["security_detail"] = n["security"]
        result.append(enrich(n))
    return result

def scan():
    """Return real scan observations; sample access points require explicit demo mode."""
    if DEMO_MODE:
        return mock_networks()
    if OS == "Linux":
        iface = get_wifi_iface()
        if not iface:
            return []
        commands = [
            (["iwlist", iface, "scan"], parse_iwlist),
            (["iw", iface, "scan"], parse_iw),
        ]
        for command, parser in commands:
            try:
                output = subprocess.check_output(
                    command, stderr=subprocess.DEVNULL, timeout=12
                ).decode("utf-8", "ignore")
                networks = parser(output)
                if networks:
                    return networks
            except (OSError, subprocess.SubprocessError):
                continue
        return []
    if OS == "Darwin":
        paths = [
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
            "/usr/sbin/airport",
        ]
        for path in paths:
            if os.path.exists(path):
                try:
                    output = subprocess.check_output(
                        [path, "-s"], stderr=subprocess.DEVNULL, timeout=12
                    ).decode("utf-8", "ignore")
                    networks = parse_airport(output)
                    if networks:
                        return networks
                except (OSError, subprocess.SubprocessError):
                    continue
        # The legacy airport binary was removed on recent macOS versions.
        try:
            output = subprocess.check_output(
                ["system_profiler", "SPAirPortDataType", "-json"],
                stderr=subprocess.DEVNULL,
                timeout=20,
            ).decode("utf-8", "ignore")
            return parse_system_profiler(output)
        except (OSError, subprocess.SubprocessError):
            return []
    if OS == "Windows":
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                stderr=subprocess.DEVNULL,
                timeout=12,
            ).decode("utf-8", "ignore")
            return parse_netsh(output)
        except (OSError, subprocess.SubprocessError):
            return []
    return []

def parse_iwlist(out):
    nets=[]
    for cell in re.split(r"Cell \d+ -", out)[1:]:
        n={}
        m=re.search(r'ESSID:"([^"]*)"',cell); n["ssid"]=m.group(1) if m else ""
        m=re.search(r"Address: ([0-9A-Fa-f:]{17})",cell); n["bssid"]=m.group(1) if m else ""
        m=re.search(r"Frequency:([\d.]+)",cell); n["frequency"]=float(m.group(1)) if m else 2.412
        m=re.search(r"Channel:(\d+)",cell); n["channel"]=int(m.group(1)) if m else 0
        m=re.search(r"Signal level=(-?\d+)",cell); n["rssi"]=int(m.group(1)) if m else -100
        n["security"]=security_from_ies(cell)
        n["security_detail"]=n["security"]
        n["band"]=frequency_band(n["frequency"] * 1000)
        nets.append(enrich(n))
    return nets

def parse_iw(out):
    nets=[]
    blocks=re.split(r"BSS ([0-9a-f:]{17})",out); i=1
    while i<len(blocks):
        bssid=blocks[i]; body=blocks[i+1] if i+1<len(blocks) else ""; i+=2
        n={"bssid":bssid.upper()}
        m=re.search(r"SSID: (.+)",body); n["ssid"]=m.group(1).strip() if m else ""
        m=re.search(r"freq: (\d+)",body); fmhz=int(m.group(1)) if m else 2412
        n["frequency"]=round(fmhz/1000,3)
        m=re.search(r"DS Parameter set: channel (\d+)",body) or re.search(r"\* primary channel: (\d+)",body)
        n["channel"]=int(m.group(1)) if m else freq_to_ch(fmhz)
        m=re.search(r"signal: (-[\d.]+) dBm",body); n["rssi"]=int(float(m.group(1))) if m else -100
        n["security"]=security_from_ies(body)
        n["security_detail"]=n["security"]
        n["band"]=frequency_band(fmhz)
        nets.append(enrich(n))
    return nets

def parse_airport(out):
    nets=[]
    for line in out.strip().split("\n")[1:]:
        p=line.split()
        if len(p)<7: continue
        n={"ssid":p[0],"bssid":p[1].upper(),"rssi":int(p[2]),"channel":int(p[3].split(",")[0])}
        fmhz=ch_to_freq(n["channel"]); n["frequency"]=round(fmhz/1000,3)
        n["security"]=p[6] if len(p)>6 else "Open"; n["security_detail"]=n["security"]
        n["band"]=frequency_band(fmhz)
        nets.append(enrich(n))
    return nets

def parse_system_profiler(out):
    nets = []
    try:
        data = json.loads(out)
        ifaces = data.get("SPAirPortDataType", [])
        for iface in ifaces:
            for net in iface.get("spairport_airport_other_local_wireless_networks", []):
                n = {}
                n["ssid"] = net.get("_name", "")
                n["bssid"] = net.get("spairport_network_bssid", "N/A").upper()
                rssi_str = net.get("spairport_signal_noise", "").split(" / ")[0]
                try: n["rssi"] = int(rssi_str.replace("dBm","").strip())
                except: n["rssi"] = -80
                ch_str = net.get("spairport_network_channel", "0")
                try: n["channel"] = int(re.search(r"\d+", ch_str).group())
                except: n["channel"] = 6
                fmhz = ch_to_freq(n["channel"])
                n["frequency"] = round(fmhz / 1000, 3)
                n["band"] = "5GHz" if fmhz > 3000 else "2.4GHz"
                n["security"] = net.get("spairport_security_mode", "Open")
                n["security_detail"] = n["security"]
                nets.append(enrich(n))
    except: pass
    return nets

def parse_netsh(out):
    nets=[]
    for block in re.split(r"SSID \d+ :",out)[1:]:
        n={}
        m=re.search(r"^\s*(.+)",block); n["ssid"]=m.group(1).strip() if m else ""
        m=re.search(r"BSSID \d+\s*:\s*([0-9a-f:]{17})",block,re.I); n["bssid"]=m.group(1).upper() if m else "N/A"
        m=re.search(r"Signal\s*:\s*(\d+)%",block); pct=int(m.group(1)) if m else 50
        n["rssi"]=int(pct/2)-100
        m=re.search(r"Channel\s*:\s*(\d+)",block); n["channel"]=int(m.group(1)) if m else 6
        fmhz=ch_to_freq(n["channel"]); n["frequency"]=round(fmhz/1000,3)
        m=re.search(r"Authentication\s*:\s*(.+)",block); n["security"]=m.group(1).strip() if m else "Open"
        n["security_detail"]=n["security"]; n["band"]=frequency_band(fmhz)
        nets.append(enrich(n))
    return nets

def channel_congestion(networks):
    congestion = {"2.4GHz": {}, "5GHz": {}, "6GHz": {}}
    for network in networks:
        channel = int(network.get("channel") or 0)
        band = network.get("band", "2.4GHz")
        if channel < 1:
            continue
        if band == "2.4GHz":
            for adjacent in range(max(1, channel - 2), min(14, channel + 3)):
                congestion["2.4GHz"][adjacent] = congestion["2.4GHz"].get(adjacent, 0) + 1
        elif band in ("5GHz", "6GHz"):
            congestion[band][channel] = congestion[band].get(channel, 0) + 1
    return congestion

def get_phy():
    info={}; iface=get_wifi_iface()
    if OS=="Linux" and iface:
        for cmd,handler in [
            (["iw","dev",iface,"link"], lambda out,info: [
                setattr_m(info,"frequency_mhz",r"freq: (\d+)",out,int),
                setattr_m(info,"tx_bitrate_mbps",r"tx bitrate: ([\d.]+) MBit/s",out,float),
                setattr_m(info,"rx_bitrate_mbps",r"rx bitrate: ([\d.]+) MBit/s",out,float),
                setattr_m(info,"mcs_index",r"MCS (\d+)",out,int),
                setattr_m(info,"signal_dbm",r"signal: (-[\d.]+) dBm",out,float),
                setattr_m(info,"connected_ssid",r"SSID: (.+)",out,str),
                setattr_m(info,"connected_bssid",r"BSSID: ([0-9A-Fa-f:]{17})",out,lambda x:x.upper()),
            ]),
        ]:
            try:
                out=subprocess.check_output(cmd,stderr=subprocess.DEVNULL,timeout=5).decode("utf-8","ignore")
                handler(out,info)
            except: pass
        try:
            out=subprocess.check_output(["iw","phy"],stderr=subprocess.DEVNULL,timeout=5).decode("utf-8","ignore")
            info["ht_support"]="HT capabilities" in out
            info["vht_support"]="VHT capabilities" in out
            info["he_support"]="HE capabilities" in out
            info["dfs_support"]="DFS" in out
            bands=[]
            if "2412 MHz" in out: bands.append("2.4GHz")
            if "5180 MHz" in out: bands.append("5GHz")
            info["supported_bands"]=bands
        except: pass
    return info

def setattr_m(d, key, pattern, text, cast):
    m=re.search(pattern,text)
    if m:
        try: d[key]=cast(m.group(1).strip())
        except: pass

def get_link():
    stats={}; iface=get_wifi_iface()
    if iface:
        try:
            c=psutil.net_io_counters(pernic=True).get(iface)
            if c:
                stats.update(tx_packets=c.packets_sent,rx_packets=c.packets_recv,
                    tx_bytes=c.bytes_sent,rx_bytes=c.bytes_recv,
                    tx_errors=c.errout,rx_errors=c.errin,tx_dropped=c.dropout,
                    rx_dropped=getattr(c,"dropin",0))
        except: pass
        if OS=="Linux":
            try:
                out=subprocess.check_output(["iw","dev",iface,"station","dump"],stderr=subprocess.DEVNULL,timeout=5).decode("utf-8","ignore")
                for key,pat in [("tx_retries",r"tx retries:\s*(\d+)"),("tx_failed",r"tx failed:\s*(\d+)"),
                                 ("missed_beacons",r"beacon loss:\s*(\d+)"),("invalid_misc",r"rx invalid nwid:\s*(\d+)")]:
                    m=re.search(pat,out)
                    if m: stats[key]=int(m.group(1))
            except: pass
    return stats

def get_diagnostics():
    diag={}; gw=None
    try:
        if OS=="Linux":
            out=subprocess.check_output(["ip","route","show","default"],stderr=subprocess.DEVNULL,timeout=3).decode()
            m=re.search(r"default via ([\d.]+)",out);
            if m: gw=m.group(1)
        elif OS=="Darwin":
            out=subprocess.check_output(["netstat","-rn"],stderr=subprocess.DEVNULL,timeout=3).decode()
            m=re.search(r"default\s+([\d.]+)",out)
            if m: gw=m.group(1)
        elif OS=="Windows":
            out=subprocess.check_output(["ipconfig"],stderr=subprocess.DEVNULL,timeout=3).decode("utf-8","ignore")
            m=re.search(r"Default Gateway.*?:\s*([\d.]+)",out)
            if m: gw=m.group(1)
    except: pass
    diag["gateway"] = gw
    try:
        target=gw or "8.8.8.8"
        cmd=["ping","-n","10",target] if OS=="Windows" else ["ping","-c","10","-i","0.2",target]
        out=subprocess.check_output(cmd,stderr=subprocess.DEVNULL,timeout=15).decode("utf-8","ignore")
        times=[float(x) for x in re.findall(r"time[=<]?([\d.]+)\s*ms",out)]
        if times:
            diag["latency_ms"]=round(sum(times)/len(times),2)
            diag["latency_min_ms"]=round(min(times),2)
            diag["latency_max_ms"]=round(max(times),2)
            jv=[abs(times[i]-times[i-1]) for i in range(1,len(times))]
            diag["jitter_ms"]=round(sum(jv)/len(jv),2) if jv else 0
            m=re.search(r"(\d+)% packet loss",out)
            diag["packet_loss_pct"]=int(m.group(1)) if m else 0
    except: pass
    try:
        import socket; t0=time.time(); socket.getaddrinfo("google.com",80)
        diag["dns_resolution_ms"]=round((time.time()-t0)*1000,2)
    except: pass
    try:
        iface=get_wifi_iface()
        if iface:
            for addr in psutil.net_if_addrs().get(iface,[]):
                if str(addr.family) in ("AddressFamily.AF_INET","2"):
                    diag["local_ip"]=addr.address; diag["subnet_mask"]=addr.netmask
    except: pass
    try:
        if OS=="Linux":
            with open("/etc/resolv.conf") as f:
                diag["dns_servers"]=re.findall(r"nameserver ([\d.]+)",f.read())
    except: pass
    return diag


def lookup_vendor(mac):
    OUI = {
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
        "00:17:88": "Philips Hue", "EC:FA:BC": "Apple", "F0:18:98": "Apple",
        "AC:BC:32": "Apple", "A4:CF:99": "Apple", "00:1A:11": "Google",
        "94:65:9C": "Google", "F4:F5:D8": "Google", "60:F1:89": "Xiaomi",
        "00:9A:CD": "Huawei", "B4:86:55": "Samsung", "8C:77:12": "Samsung",
        "00:50:F2": "Microsoft", "28:D2:44": "Microsoft", "DC:A4:CA": "Espressif",
        "24:6F:28": "Espressif", "30:AE:A4": "Espressif", "FC:F5:C4": "Espressif",
        "00:23:24": "Intel", "8C:EC:4B": "Intel", "AC:FD:CE": "TP-Link",
        "50:C7:BF": "TP-Link", "14:EB:B6": "TP-Link", "08:00:27": "VirtualBox",
        "00:0C:29": "VMware", "00:15:5D": "Microsoft Hyper-V",
    }
    return OUI.get(mac[:8].upper(), "")

def get_hostname(ip):
    try:
        import socket
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def get_devices():
    devices = []
    try:
        out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL, timeout=10).decode("utf-8", "ignore")
        if OS == "Windows":
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]{17})\s+(\S+)", line, re.I)
                if m:
                    ip, mac, flags = m.group(1), m.group(2).replace("-", ":").upper(), m.group(3)
                    devices.append({"ip": ip, "mac": mac, "flags": flags, "vendor": lookup_vendor(mac), "hostname": ""})
        else:
            for line in out.splitlines():
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", line, re.I)
                if m:
                    ip, mac = m.group(1), m.group(2).upper()
                    devices.append({"ip": ip, "mac": mac, "flags": "C", "vendor": lookup_vendor(mac), "hostname": get_hostname(ip)})
    except:
        pass
    return devices


def run_speedtest():
    try:
        import urllib.request, time, threading
        results = {"download": 0, "upload": 0, "ping": 0}

        start = time.time()
        urllib.request.urlopen("http://8.8.8.8", timeout=5)
        results["ping"] = round((time.time() - start) * 1000, 1)

        start = time.time()
        with urllib.request.urlopen("https://speed.cloudflare.com/__down?bytes=10000000", timeout=30) as r:
            size = len(r.read())
        elapsed = time.time() - start
        results["download"] = round((size * 8) / (elapsed * 1_000_000), 1)

        import io
        data = b"0" * 1_000_000
        req = urllib.request.Request("https://speed.cloudflare.com/__up", data=data, method="POST")
        start = time.time()
        urllib.request.urlopen(req, timeout=30)
        elapsed = time.time() - start
        results["upload"] = round((len(data) * 8) / (elapsed * 1_000_000), 1)

        return results
    except Exception as e:
        return {"download": 0, "upload": 0, "ping": 0, "error": str(e)}


def has_wifi():
    try:
        if OS == "Windows":
            import subprocess
            out = subprocess.check_output(["netsh","wlan","show","interfaces"],stderr=subprocess.DEVNULL).decode()
            return {"has_wifi": "Name" in out}
        elif OS == "Darwin":
            import subprocess
            out = subprocess.check_output(["networksetup","-listallhardwareports"],stderr=subprocess.DEVNULL).decode()
            return {"has_wifi": "Wi-Fi" in out}
        else:
            import os as _os
            ifaces = _os.listdir("/sys/class/net/")
            wireless = [i for i in ifaces if _os.path.exists(f"/sys/class/net/{i}/wireless")]
            return {"has_wifi": len(wireless) > 0, "interfaces": wireless}
    except:
        return {"has_wifi": False}

def get_system():
    try:
        import psutil, platform, socket
        cpu = psutil.cpu_percent(interval=0.5)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        temp = None
        try:
            temps = psutil.sensors_temperatures()
            for k in ["coretemp","cpu_thermal","k10temp"]:
                if k in temps and temps[k]:
                    temp = round(temps[k][0].current, 1)
                    break
        except: pass
        uptime_s = int(__import__("time").time() - psutil.boot_time())
        h, m = divmod(uptime_s // 60, 60)
        uptime = f"{h}h {m}m"
        wifi_adapter = ""
        try:
            import subprocess, re
            out = subprocess.check_output(["lspci"], stderr=subprocess.DEVNULL).decode()
            m2 = re.search(r"Network controller: (.+)", out)
            if m2: wifi_adapter = m2.group(1).strip()[:40]
        except: pass
        return {
            "cpu_pct": round(cpu, 1),
            "ram_pct": round(ram.percent, 1),
            "ram_used_gb": round(ram.used/1e9, 1),
            "ram_total_gb": round(ram.total/1e9, 1),
            "disk_pct": round(disk.percent, 1),
            "disk_used_gb": round(disk.used/1e9, 1),
            "disk_total_gb": round(disk.total/1e9, 1),
            "cpu_temp": temp,
            "temp_max": 80,
            "os": f"{platform.system()} {platform.release()}",
            "hostname": socket.gethostname(),
            "uptime": uptime,
            "wifi_adapter": wifi_adapter,
        }
    except Exception as e:
        return {"error": str(e)}

# ── Static file serving ───────────────────────────────────────────────────────
# PyInstaller one-file bundles extract resources into _MEIPASS.
APP_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.realpath(os.path.join(APP_DIR, "dist"))


def resolve_static_path(path):
    decoded = unquote(path or "/")
    relative = decoded.lstrip("/") or "index.html"
    candidate = os.path.realpath(os.path.join(STATIC_DIR, relative))
    try:
        if os.path.commonpath((STATIC_DIR, candidate)) != STATIC_DIR:
            return None
    except ValueError:
        return None
    if not os.path.isfile(candidate):
        if not os.path.splitext(relative)[1]:
            candidate = os.path.join(STATIC_DIR, "index.html")
        else:
            return None
    return candidate if os.path.isfile(candidate) else None


def serve_static(handler, path):
    filepath = resolve_static_path(path)
    if filepath is None:
        handler.send_response(404)
        handler.send_header("Content-Length", "0")
        handler.end_headers()
        return
    mime, _ = mimetypes.guess_type(filepath)
    mime = mime or "application/octet-stream"
    with open(filepath, "rb") as stream:
        data = stream.read()
    handler.send_response(200)
    handler.send_header("Content-Type", mime)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    if os.path.basename(filepath) == "index.html":
        handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


# ── HTTP Handler ──────────────────────────────────────────────────────────────
def _collect_site_ids(value):
    """Extract declared site identifiers from nested site/feature request payloads."""
    found = []

    def visit(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if key == "site_id":
                    found.append(child.strip() if isinstance(child, str) else None)
                elif key in {"site_ids", "site_allowlist"}:
                    if isinstance(child, list):
                        found.extend(value.strip() if isinstance(value, str) else None for value in child)
                    else:
                        found.append(None)
                else:
                    visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return list(dict.fromkeys(found))

class Handler(BaseHTTPRequestHandler):
    MAX_JSON_BODY = 1024 * 1024

    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} {args[0]} {args[1]}")

    def add_common_headers(self):
        origin = self.headers.get("Origin")
        if origin in CORS_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def send_json(self, data, status=200, headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for header_name, header_value in (headers or {}).items():
            self.send_header(header_name, str(header_value))
        self.add_common_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_capture_file(self, path, capture_id):
        size = path.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
        self.send_header("Content-Disposition", f'attachment; filename="wifi-analyzer-{capture_id}.pcap"')
        self.send_header("Content-Length", str(size))
        self.add_common_headers()
        self.end_headers()
        with path.open("rb") as capture_file:
            while chunk := capture_file.read(64 * 1024):
                self.wfile.write(chunk)

    def bearer_token(self):
        value = self.headers.get("Authorization", "")
        scheme, separator, token = value.partition(" ")
        if separator and scheme.lower() == "bearer":
            return token.strip() or None
        return None

    def origin_allowed(self):
        origin = self.headers.get("Origin")
        if not origin or origin in CORS_ORIGINS:
            return True
        parsed = urlparse(origin)
        # Same-origin desktop/self-hosted deployments may use a LAN hostname
        # instead of localhost; allow only an exact Host match in that case.
        return parsed.scheme in {"http", "https"} and parsed.netloc == self.headers.get("Host")

    def audit_event(self, action, *, actor=None, target_type=None, target_id=None, outcome="success", metadata=None):
        if actor is None:
            actor = AUTH.identity(self.bearer_token())
        request_id = self.headers.get("X-Request-ID")
        try:
            return AUDIT.record(
                action, actor=actor, target_type=target_type, target_id=target_id,
                outcome=outcome, metadata=metadata, request_id=request_id,
            )
        except Exception:
            # Audit failures are visible without printing request bodies or secrets.
            print(f"[AUDIT ERROR] Could not persist event: {action}")
            return None

    def enforce_rate_limit(self, policy_name, *, client_only=False):
        policy = RATE_LIMIT_POLICIES.get(policy_name)
        if policy is None:
            return True
        capacity, period_seconds = policy
        peer_ip = str(self.client_address[0]) if self.client_address else "unknown"
        identity = None if client_only else AUTH.identity(self.bearer_token())
        principal = f"user:{identity['id']}" if identity else f"ip:{peer_ip}"
        decision = RATE_LIMITER.consume(
            f"{policy_name}:{principal}",
            capacity=capacity,
            period_seconds=period_seconds,
        )
        if decision["allowed"]:
            return True
        retry_after = decision["retry_after_seconds"]
        self.send_json(
            {
                "error": "Rate limit exceeded",
                "retry_after_seconds": retry_after,
                "limit": decision["limit"],
            },
            429,
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(decision["limit"]),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(decision["reset_after_seconds"]),
            },
        )
        return False

    def enforce_subscription_capacity(self, resource, used):
        decision = BILLING.capacity(resource, used)
        if decision["allowed"]:
            return True
        self.send_json({
            "error": "The current plan limit has been reached",
            "code": "plan_limit_reached",
            **decision,
            "upgrade_required": True,
        }, 402)
        return False

    def require_auth(self, permission=None):
        token = self.bearer_token()
        if not AUTH.validate(token):
            self.send_json({"error": "Authentication required"}, 401)
            return False
        if permission and not AUTH.has_permission(token, permission):
            route_id = re.sub(r"[^A-Za-z0-9._:@-]", "_", urlparse(self.path).path.strip("/"))[:128] or "unknown"
            self.audit_event(
                "authorization.denied", outcome="denied",
                target_type="api_route", target_id=route_id,
                metadata={"required_permission": permission, "permission": permission},
            )
            self.send_json({"error": "Insufficient permissions", "required_permission": permission}, 403)
            return False
        return True

    def require_site_access(self, site_ids, *, require_explicit=False):
        scope = AUTH.site_access(self.bearer_token())
        if scope is None:
            self.send_json({"error": "Authentication required"}, 401)
            return False
        if scope["all_sites"]:
            return True
        if not isinstance(site_ids, list) or (require_explicit and not site_ids):
            self.send_json({"error": "An explicit site assignment is required for this operation"}, 403)
            return False
        if any(not isinstance(site_id, str) or site_id not in scope["site_ids"] for site_id in site_ids):
            self.send_json({"error": "One or more sites are outside your assigned access scope"}, 403)
            return False
        return True

    def require_webhook_delivery_site_access(self, delivery):
        if not isinstance(delivery, dict):
            self.send_json({"error": "Webhook delivery not found"}, 404)
            return False
        scope = AUTH.site_access(self.bearer_token())
        if scope is None:
            self.send_json({"error": "Authentication required"}, 401)
            return False
        if scope["all_sites"]:
            return True
        delivery_sites = delivery.get("site_ids")
        if (
            delivery.get("has_unscoped_events")
            or not isinstance(delivery_sites, list)
            or not delivery_sites
            or not set(delivery_sites).issubset(scope["site_ids"])
        ):
            self.send_json({"error": "Webhook delivery not found"}, 404)
            return False
        return True

    def require_report_job_site_access(self, job):
        if not isinstance(job, dict):
            self.send_json({"error": "Report job not found"}, 404)
            return False
        scope = AUTH.site_access(self.bearer_token())
        if scope is None:
            self.send_json({"error": "Authentication required"}, 401)
            return False
        if scope["all_sites"]:
            return True
        job_sites = job.get("site_ids")
        if not isinstance(job_sites, list) or not job_sites:
            self.send_json({"error": "Report job not found"}, 404)
            return False
        if not set(job_sites).issubset(scope["site_ids"]):
            self.send_json({"error": "Report job not found"}, 404)
            return False
        return True

    def require_agent_site_access(self, agent_id):
        assignment = AGENT_HEALTH.get_agent_scope(agent_id)
        if assignment is None:
            self.send_json({"error": "Agent not found"}, 404)
            return False
        scope = AUTH.site_access(self.bearer_token())
        if scope is None:
            self.send_json({"error": "Authentication required"}, 401)
            return False
        site_id = assignment.get("site_id")
        if not scope["all_sites"] and (site_id is None or site_id not in scope["site_ids"]):
            # Hide the existence of agents belonging to another site.
            self.send_json({"error": "Agent not found"}, 404)
            return False
        return True

    def visible_agent_records(self, records):
        scope = AUTH.site_access(self.bearer_token())
        if scope is None or scope["all_sites"]:
            return records
        assigned = {
            item["agent_id"]: item.get("site_id")
            for item in AGENT_HEALTH.list_agent_credentials()
        }
        return [
            item for item in records
            if (item.get("site_id") if item.get("site_id") is not None else assigned.get(item.get("agent_id")))
            in scope["site_ids"]
        ]

    def read_raw_body(self, maximum_bytes):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            raise ValueError("Invalid Content-Length")
        if length <= 0 or length > maximum_bytes:
            raise ValueError("Request body is empty or exceeds the configured limit")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("Content-Type must be application/json")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("Request body was truncated")
        return raw

    def read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            raise ValueError("Invalid Content-Length")
        if length < 0 or length > self.MAX_JSON_BODY:
            raise ValueError("Request body exceeds the 1 MiB limit")
        if length == 0:
            return {}
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("Content-Type must be application/json")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Request body must contain valid JSON")
        if not isinstance(payload, dict):
            raise ValueError("Request JSON must be an object")
        return payload

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        self.send_response(204)
        if origin in CORS_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Vary", "Origin")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        request_url = urlparse(self.path)
        path = request_url.path
        if path == "/api/auth/status":
            self.send_json(AUTH.status(self.bearer_token()))
            return
        if path.startswith("/api/"):
            permission = "diagnostics.read"
            if path.startswith("/api/capture/"):
                permission = "diagnostics.run"
            elif path.startswith("/api/reports/jobs"):
                permission = "reports.read"
            elif path.startswith("/api/webhooks/"):
                permission = "webhooks.read"
            elif path in {"/api/agents/credentials", "/api/agents/negotiations"}:
                permission = "agents.manage"
            elif path.startswith("/api/agents/"):
                permission = "agents.read"
            elif path == "/api/sites" or path.startswith("/api/sites/history"):
                permission = "sites.read"
            elif path == "/api/adapters":
                permission = "agents.read"
            elif path.startswith("/api/security/audit"):
                permission = "users.manage"
            elif path == "/api/billing/status":
                permission = "billing.manage"
            elif path == "/api/users":
                permission = "users.manage"
            if not self.require_auth(permission):
                return

        if path == "/api/billing/status":
            try:
                usage = {
                    "users": len(AUTH.list_users(self.bearer_token())),
                    "agents": sum(1 for item in AGENT_HEALTH.list_agent_credentials() if item["status"] == "active"),
                    "webhook_subscriptions": len(WEBHOOK_SUBSCRIPTIONS.list_subscriptions()),
                }
                billing_status = BILLING.status()
                billing_status["usage"] = usage
                billing_status["portal_available"] = bool(BILLING.stripe_customer_id())
                available_plans = [
                    {
                        "plan_id": plan_id,
                        "label": definition["label"],
                        "limits": dict(definition["limits"]),
                        "available_for_checkout": plan_id in configured_price_plans().values(),
                    }
                    for plan_id, definition in PLAN_CATALOG.items()
                ]
                self.send_json({"billing": billing_status, "plans": available_plans})
            except ValueError as error:
                self.send_json({"error": str(error)}, 503)
            except Exception:
                self.send_json({"error": "Billing status is temporarily unavailable"}, 503)
            return

        if path == "/api/webhooks/subscriptions":
            scope = AUTH.site_access(self.bearer_token())
            site_filter = None if scope["all_sites"] else scope["site_ids"]
            try:
                subscriptions = WEBHOOK_SUBSCRIPTIONS.list_subscriptions(site_ids=site_filter)
                self.send_json({"subscriptions": subscriptions, "subscription_count": len(subscriptions)})
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
            return

        if path == "/api/webhooks/deliveries/report":
            scope = AUTH.site_access(self.bearer_token())
            site_filter = None if scope["all_sites"] else scope["site_ids"]
            parameters = parse_qs(request_url.query, keep_blank_values=True)
            window_values = parameters.get("window_days", ["7"])
            if len(window_values) != 1 or not window_values[0].isdigit():
                self.send_json({"error": "window_days must be an integer from 1 to 90"}, 400)
                return
            window_days = int(window_values[0])
            now = datetime.now(timezone.utc)
            try:
                records = WEBHOOK_DELIVERIES.analytics_records(
                    site_ids=site_filter,
                    window_days=window_days,
                    now=now,
                    limit=5000,
                )
                report = run_feature(
                    "router_webhook_delivery_health_report",
                    {
                        "now": now.isoformat(),
                        "window_days": window_days,
                        "deliveries": records,
                    },
                )
                self.send_json({"report": report["result"]})
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
            return

        if path == "/api/webhooks/deliveries":
            scope = AUTH.site_access(self.bearer_token())
            site_filter = None if scope["all_sites"] else scope["site_ids"]
            try:
                self.send_json({
                    "summary": WEBHOOK_DELIVERIES.summary(site_ids=site_filter),
                    "deliveries": WEBHOOK_DELIVERIES.list_deliveries(limit=100, site_ids=site_filter),
                })
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
            return
        delivery_detail = re.fullmatch(r"/api/webhooks/deliveries/([1-9][0-9]*)", path)
        if delivery_detail:
            delivery = WEBHOOK_DELIVERIES.get(int(delivery_detail.group(1)))
            if not self.require_webhook_delivery_site_access(delivery):
                return
            self.send_json({"delivery": delivery})
            return

        if path == "/api/scan" and not self.enforce_rate_limit("api.scan"):
            return
        if path == "/api/speedtest" and not self.enforce_rate_limit("api.speedtest"):
            return

        if path == "/api/capture/interfaces":
            self.send_json(LIVE_CAPTURE.list_interfaces())
            return
        if path == "/api/capture/status":
            self.send_json(LIVE_CAPTURE.status())
            return
        capture_download = re.fullmatch(r"/api/capture/([a-f0-9]{32})/download", path)
        if capture_download:
            capture_id = capture_download.group(1)
            capture_path = LIVE_CAPTURE.capture_file(capture_id)
            if capture_path is None:
                self.send_json({"error": "Capture not found or not ready for download"}, 404)
                return
            self.audit_event(
                "capture.downloaded", target_type="packet_capture", target_id=capture_id,
                metadata={"captured_bytes": capture_path.stat().st_size},
            )
            self.send_capture_file(capture_path, capture_id)
            return

        api_routes = {
            "/api/users": lambda: {"users": AUTH.list_users(self.bearer_token())},
            "/api/security/audit/summary": AUDIT.summary,
            "/api/scan": lambda: {
                "networks": (networks := scan()),
                "congestion": channel_congestion(networks),
                "timestamp": time.time(),
                "source": "demo" if DEMO_MODE else "live",
                "interface": get_wifi_iface(),
            },
            "/api/system": get_system,
            "/api/phy": get_phy,
            "/api/link": get_link,
            "/api/diagnostics": get_diagnostics,
            "/api/has_wifi": has_wifi,
            "/api/devices": lambda: {"devices": get_devices()},
            "/api/speedtest": run_speedtest,
            "/api/features": lambda: {
                "count": len(feature_catalog()),
                "features": feature_catalog(),
            },
            "/api/adapters": lambda: {
                "count": len(router_adapter_manifests()),
                "adapters": router_adapter_manifests(),
            },
            "/api/agents/credentials": lambda: {
                "credentials": self.visible_agent_records(AGENT_HEALTH.list_agent_credentials()),
            },
            "/api/agents/negotiations": lambda: {
                "negotiations": self.visible_agent_records(AGENT_HEALTH.list_latest_agent_negotiations()),
            },
            "/api/agents/health": lambda: run_feature("router_agent_health_report", {
                "agents": self.visible_agent_records(AGENT_HEALTH.list_agents()),
                "now": datetime.now(timezone.utc).isoformat(),
                "stale_after_seconds": 180,
            }),
            "/api/capabilities": lambda: {
                "name": "WiFi Analyzer Pro",
                "version": APP_VERSION,
                "platform": OS,
                "mode": "demo" if DEMO_MODE else "live",
                "wifi_interface": get_wifi_iface(),
                "feature_tool_count": len(feature_catalog()),
                "features": {"wireless_scan": True, "channel_analysis": True, "device_discovery": True, "speed_test": True},
                "security": {
                    "authentication": True,
                    "auth_configured": AUTH.configured(),
                    "remote_access": "Use a VPN or authenticated reverse proxy",
                },
            },
            "/health": lambda: {"status": "ok", "version": APP_VERSION, "os": OS, "mode": "demo" if DEMO_MODE else "live"},
        }
        try:
            if path == "/api/reports/jobs":
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=10)
                def single_job_parameter(name):
                    values = params.get(name, [])
                    if len(values) > 1:
                        raise ValueError(f"{name} may be supplied only once")
                    return values[0] if values else None
                raw_limit = single_job_parameter("limit")
                try:
                    limit = 50 if raw_limit is None else int(raw_limit)
                except ValueError as error:
                    raise ValueError("limit must be an integer") from error
                job_scope = AUTH.site_access(self.bearer_token())
                site_filter = None if job_scope["all_sites"] else job_scope["site_ids"]
                self.send_json({
                    "summary": REPORT_JOBS.summary(site_ids=site_filter),
                    "jobs": REPORT_JOBS.list_jobs(
                        status=single_job_parameter("status") or None,
                        schedule_id=single_job_parameter("schedule_id") or None,
                        limit=limit,
                        site_ids=site_filter,
                    ),
                })
            elif path.startswith("/api/reports/jobs/"):
                identifier = unquote(path[len("/api/reports/jobs/"):])
                if not identifier.isdigit() or "/" in identifier:
                    self.send_json({"error": "Report job not found"}, 404)
                    return
                job = REPORT_JOBS.get(int(identifier), include_bundle=False)
                if job is None:
                    self.send_json({"error": "Report job not found"}, 404)
                    return
                if not self.require_report_job_site_access(job):
                    return
                self.send_json({"job": job})
            elif path != "/api/agents/negotiations" and path.startswith("/api/agents/") and path.endswith("/negotiations"):
                agent_id = unquote(path[len("/api/agents/"):-len("/negotiations")]).strip("/")
                if not agent_id or "/" in agent_id:
                    self.send_json({"error": "Agent negotiation history not found"}, 404)
                    return
                if not self.require_agent_site_access(agent_id):
                    return
                self.send_json({
                    "negotiations": AGENT_HEALTH.get_agent_negotiations(agent_id, limit=20)
                })
            elif path == "/api/agents/snapshots":
                self.send_json({"snapshots": self.visible_agent_records(AGENT_HEALTH.list_latest_snapshots())})
            elif path.startswith("/api/agents/snapshots/") and path.endswith("/diff"):
                agent_id = unquote(path[len("/api/agents/snapshots/"):-len("/diff")])
                if not agent_id or "/" in agent_id:
                    self.send_json({"error": "Agent snapshot diff not found"}, 404)
                    return
                if not self.require_agent_site_access(agent_id):
                    return
                snapshots = AGENT_HEALTH.get_recent_snapshots(agent_id, limit=2)
                if not snapshots:
                    self.send_json({"error": "Agent snapshot not found"}, 404)
                    return
                previous = snapshots[0] if len(snapshots) > 1 else None
                current = snapshots[-1]
                report = run_feature("openwrt_agent_snapshot_diff", {
                    "previous": previous,
                    "current": current,
                })
                self.send_json(report)
            elif path.startswith("/api/agents/snapshots/"):
                agent_id = unquote(path[len("/api/agents/snapshots/"):])
                if not agent_id or "/" in agent_id:
                    self.send_json({"error": "Agent snapshot not found"}, 404)
                    return
                if not self.require_agent_site_access(agent_id):
                    return
                snapshot = AGENT_HEALTH.get_latest_snapshot(agent_id)
                if snapshot is None:
                    self.send_json({"error": "Agent snapshot not found"}, 404)
                else:
                    self.send_json({"snapshot": snapshot})
            elif path == "/api/security/audit":
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=10)
                def audit_parameter(name):
                    values = params.get(name, [])
                    if len(values) > 1:
                        raise ValueError(f"{name} may be supplied only once")
                    return values[0] if values else None
                try:
                    raw_limit = audit_parameter("limit")
                    raw_before_id = audit_parameter("before_id")
                    limit = 50 if raw_limit is None else int(raw_limit)
                    before_id = None if raw_before_id is None else int(raw_before_id)
                except ValueError as error:
                    raise ValueError("limit and before_id must be integers") from error
                events = AUDIT.list_events(
                    limit=limit, before_id=before_id,
                    action=audit_parameter("action"),
                    outcome=audit_parameter("outcome"),
                    actor_username=audit_parameter("actor_username"),
                )
                self.send_json({"summary": AUDIT.summary(), "events": events,
                                "next_before_id": events[-1]["id"] if len(events) == limit else None})
            elif path == "/api/security/audit/verify":
                self.send_json({"verification": AUDIT.verify_chain()})
            elif path == "/api/security/audit/checkpoint":
                try:
                    checkpoint = create_signed_checkpoint(AUDIT)
                except ValueError as error:
                    self.send_json({"error": str(error)}, 409)
                    return
                except RuntimeError:
                    self.send_json({"error": "Audit checkpoint signing is unavailable; inspect the local key file and permissions."}, 503)
                    return
                self.send_json({"checkpoint": checkpoint})
            elif path == "/api/security/audit/summary":
                self.send_json({"summary": AUDIT.summary()})
            elif path == "/api/sites":
                scope = AUTH.site_access(self.bearer_token())
                discovered = set(HISTORY.site_ids(limit=100))
                discovered.update(
                    credential["site_id"]
                    for credential in AGENT_HEALTH.list_agent_credentials()
                    if credential.get("site_id")
                )
                ordered_sites = sorted(discovered)[:100]
                site_ids = ordered_sites if scope["all_sites"] else [
                    site_id for site_id in ordered_sites if site_id in scope["site_ids"]
                ]
                self.send_json({"site_ids": site_ids, "all_sites": scope["all_sites"]})
            elif path == "/api/sites/history/report":
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=10)
                values = params.get("site_ids", [])
                if len(values) > 1:
                    raise ValueError("site_ids may be supplied only once")
                if values and values[0].strip():
                    site_ids = [item.strip() for item in values[0].split(",") if item.strip()]
                else:
                    scope = AUTH.site_access(self.bearer_token())
                    discovered = HISTORY.site_ids(limit=100)
                    site_ids = discovered if scope["all_sites"] else [
                        site_id for site_id in discovered if site_id in scope["site_ids"]
                    ]
                    site_ids = site_ids[:20]
                if len(site_ids) > 20:
                    raise ValueError("site_ids may contain no more than 20 sites")
                if not self.require_site_access(site_ids):
                    return
                pairs = HISTORY.latest_pairs(site_ids)
                report = run_feature("site_to_site_change_report", {"sites": pairs})
                self.send_json({
                    "report": report,
                    "requested_site_count": len(site_ids),
                    "reported_site_count": report["result"]["summary"]["site_count"],
                })
            elif path == "/api/sites/history":
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=10)
                def single_parameter(name):
                    values = params.get(name, [])
                    if len(values) > 1:
                        raise ValueError(f"{name} may be supplied only once")
                    return values[0] if values else None
                raw_limit = single_parameter("limit")
                raw_before_id = single_parameter("before_id")
                raw_site_id = single_parameter("site_id")
                try:
                    limit = 50 if raw_limit is None else int(raw_limit)
                    before_id = None if raw_before_id is None else int(raw_before_id)
                except ValueError as error:
                    raise ValueError("limit and before_id must be integers") from error
                scope = AUTH.site_access(self.bearer_token())
                if raw_site_id is not None:
                    if not self.require_site_access([raw_site_id]):
                        return
                    snapshots = HISTORY.list(site_id=raw_site_id, limit=limit, before_id=before_id)
                elif scope["all_sites"]:
                    snapshots = HISTORY.list(limit=limit, before_id=before_id)
                else:
                    snapshots = HISTORY.list(
                        site_ids=scope["site_ids"], limit=limit, before_id=before_id
                    )
                self.send_json({
                    "snapshots": snapshots,
                    "next_before_id": snapshots[-1]["id"] if len(snapshots) == limit else None,
                })
            elif path.startswith("/api/sites/history/"):
                identifier = unquote(path[len("/api/sites/history/"):])
                if not identifier or "/" in identifier:
                    self.send_json({"error": "Snapshot not found"}, 404)
                    return
                try:
                    snapshot_id = int(identifier)
                except ValueError:
                    self.send_json({"error": "Snapshot not found"}, 404)
                    return
                snapshot = HISTORY.get(snapshot_id)
                if snapshot is None or not AUTH.can_access_site(
                    self.bearer_token(), snapshot["site_id"]
                ):
                    self.send_json({"error": "Snapshot not found"}, 404)
                else:
                    self.send_json({"snapshot": snapshot})
            elif path in api_routes:
                self.send_json(api_routes[path]())
            elif path.startswith("/api/"):
                self.send_json({"error": "Not found"}, 404)
            else:
                serve_static(self, path)
        except (BrokenPipeError, ConnectionResetError):
            return
        except ValueError as error:
            self.send_json({"error": str(error)}, 400)
        except Exception as error:
            print(f"[ERROR] {path}: {error}")
            if not self.wfile.closed:
                self.send_json({"error": "Internal server error"}, 500)

    def do_POST(self):
        path = urlparse(self.path).path
        if not self.origin_allowed():
            self.send_json({"error": "Origin is not allowed"}, 403)
            return

        if path == "/api/billing/webhook":
            if not self.enforce_rate_limit("api.billing.webhook", client_only=True):
                return
            webhook_secret = os.getenv("WIFI_ANALYZER_STRIPE_WEBHOOK_SECRET", "")
            if not webhook_secret:
                self.send_json({"error": "Stripe webhook signing secret is not configured"}, 503)
                return
            try:
                raw_body = self.read_raw_body(256 * 1024)
                event = verify_stripe_signature(
                    raw_body, self.headers.get("Stripe-Signature"), webhook_secret,
                )
                processed = BILLING.process_stripe_event(
                    event, price_plans=configured_price_plans(),
                )
            except StripeSignatureError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except Exception:
                self.send_json({"error": "Billing webhook processing failed"}, 503)
                return
            self.audit_event(
                "billing.webhook.received",
                target_type="billing_event",
                target_id=event["id"],
                metadata={"event_type": event["type"], "duplicate": not processed},
            )
            self.send_json({"received": True, "duplicate": not processed})
            return

        if path in {"/api/billing/checkout", "/api/billing/portal"}:
            if not self.require_auth("billing.manage"):
                return

        # Authenticate diagnostic controls before rate limiting them, but rate
        # limit login/setup before parsing or deriving expensive credentials.
        if path.startswith("/api/capture/") and not self.require_auth("diagnostics.run"):
            return
        if path.startswith("/api/auth/mfa/") and not self.require_auth():
            return
        rate_policy = {
            "/api/auth/setup": ("auth.setup", True),
            "/api/auth/login": ("auth.login", True),
            "/api/auth/mfa/setup": ("auth.mfa", False),
            "/api/auth/mfa/confirm": ("auth.mfa", False),
            "/api/auth/mfa/disable": ("auth.mfa", False),
            "/api/sites/audit": ("api.site.audit", False),
            "/api/capture/start": ("api.capture.start", False),
            "/api/reports/jobs/enqueue": ("api.report.enqueue", False),
            "/api/webhooks/deliveries/enqueue": ("api.webhook.enqueue", False),
        }.get(path)
        if rate_policy and not self.enforce_rate_limit(rate_policy[0], client_only=rate_policy[1]):
            return
        if path.startswith("/api/webhooks/subscriptions/") and path.endswith("/probe"):
            if not self.enforce_rate_limit("api.webhook.probe"):
                return
        elif path.startswith("/api/webhooks/subscriptions") and not self.enforce_rate_limit("api.webhook.manage"):
            return
        if path.startswith("/api/features/") and not self.enforce_rate_limit("api.feature.execution"):
            return

        if path == "/api/auth/logout":
            actor = AUTH.identity(self.bearer_token())
            if not AUTH.logout(self.bearer_token()):
                self.send_json({"error": "Invalid or expired session"}, 401)
                return
            self.audit_event("auth.logout.succeeded", actor=actor, target_type="user",
                             target_id=actor["id"] if actor else None)
            self.send_json({"ok": True})
            return

        try:
            payload = self.read_json_body()
        except ValueError as error:
            self.send_json({"error": str(error)}, 400)
            return

        if path == "/api/billing/checkout":
            plan_id = payload.get("plan_id")
            if plan_id not in {"pro", "business", "enterprise"}:
                self.send_json({"error": "plan_id must be pro, business or enterprise"}, 400)
                return
            current = BILLING.status()
            if current["active"]:
                self.send_json({"error": "An active subscription already exists; use the billing portal to change or cancel it"}, 409)
                return
            try:
                prices = configured_price_plans()
                price_id = next((price for price, mapped_plan in prices.items() if mapped_plan == plan_id), None)
                if not price_id:
                    self.send_json({"error": f"Stripe price for the {plan_id} plan is not configured"}, 503)
                    return
                secret_key = os.getenv("WIFI_ANALYZER_STRIPE_SECRET_KEY", "")
                public_url = os.getenv("WIFI_ANALYZER_PUBLIC_URL", "")
                if not secret_key or not public_url:
                    self.send_json({"error": "Stripe secret key and public application URL must be configured on the server"}, 503)
                    return
                result = create_checkout_session(
                    secret_key=secret_key,
                    price_id=price_id,
                    instance_id=BILLING.instance_id(),
                    public_url=public_url,
                    customer_id=BILLING.stripe_customer_id(),
                )
            except StripeApiError as error:
                self.send_json({"error": str(error)}, 502)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event("billing.checkout.created", target_type="billing_plan", target_id=plan_id)
            self.send_json({"checkout": result})
            return

        if path == "/api/billing/portal":
            customer_id = BILLING.stripe_customer_id()
            if not customer_id:
                self.send_json({"error": "No Stripe customer is linked to this workspace yet"}, 409)
                return
            try:
                secret_key = os.getenv("WIFI_ANALYZER_STRIPE_SECRET_KEY", "")
                public_url = os.getenv("WIFI_ANALYZER_PUBLIC_URL", "")
                if not secret_key or not public_url:
                    self.send_json({"error": "Stripe secret key and public application URL must be configured on the server"}, 503)
                    return
                result = create_billing_portal_session(
                    secret_key=secret_key,
                    customer_id=customer_id,
                    public_url=public_url,
                )
            except StripeApiError as error:
                self.send_json({"error": str(error)}, 502)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event("billing.portal.created", target_type="billing_customer")
            self.send_json({"portal": result})
            return

        if path == "/api/auth/setup":
            try:
                token = AUTH.setup(payload.get("password"), payload.get("username", "admin"))
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except RuntimeError as error:
                self.send_json({"error": str(error)}, 409)
                return
            identity = AUTH.identity(token)
            self.audit_event("auth.setup.completed", actor=identity, target_type="user",
                             target_id=identity["id"] if identity else None)
            self.send_json({"token": token, "status": AUTH.status(token)}, 201)
            return

        if path == "/api/auth/login":
            try:
                token = AUTH.login(
                    payload.get("password"),
                    payload.get("username", "admin"),
                    code=payload.get("code"),
                )
            except MFARequiredError as error:
                self.send_json({"error": str(error), "mfa_required": True}, 401)
                return
            except (PermissionError, RuntimeError) as error:
                if isinstance(error, PermissionError) and "five minutes" in str(error):
                    supplied_username = payload.get("username", "admin")
                    username = (
                        supplied_username.strip().lower()
                        if isinstance(supplied_username, str)
                        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", supplied_username.strip())
                        else None
                    )
                    self.audit_event(
                        "auth.login.lockout", outcome="denied",
                        target_type="authentication", target_id=username,
                        metadata={"username": username} if username else None,
                    )
                self.send_json({"error": str(error)}, 401)
                return
            identity = AUTH.identity(token)
            self.audit_event("auth.login.succeeded", actor=identity, target_type="user",
                             target_id=identity["id"] if identity else None)
            self.send_json({"token": token, "status": AUTH.status(token)})
            return

        if path == "/api/auth/mfa/setup":
            try:
                result = AUTH.begin_mfa_setup(self.bearer_token(), payload.get("password"))
            except PermissionError as error:
                self.send_json({"error": str(error)}, 403)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except RuntimeError as error:
                self.send_json({"error": str(error)}, 409)
                return
            self.audit_event("auth.mfa.enrollment.started", target_type="user")
            self.send_json({"setup": result})
            return

        if path == "/api/auth/mfa/confirm":
            try:
                result = AUTH.confirm_mfa_setup(
                    self.bearer_token(), payload.get("password"), payload.get("code")
                )
            except PermissionError as error:
                self.send_json({"error": str(error)}, 403)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except RuntimeError as error:
                self.send_json({"error": str(error)}, 409)
                return
            self.audit_event(
                "auth.mfa.enabled", target_type="user",
                metadata={"recovery_codes_issued": result["recovery_codes_remaining"]},
            )
            self.send_json({"mfa": result})
            return

        if path == "/api/auth/mfa/disable":
            try:
                result = AUTH.disable_mfa(
                    self.bearer_token(), payload.get("password"), payload.get("code")
                )
            except PermissionError as error:
                self.send_json({"error": str(error)}, 403)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except RuntimeError as error:
                self.send_json({"error": str(error)}, 409)
                return
            self.audit_event("auth.mfa.disabled", target_type="user")
            self.send_json({"mfa": result})
            return

        if path == "/api/users":
            if not self.require_auth("users.manage"):
                return
            try:
                with BILLING_QUOTA_LOCK:
                    users_now = AUTH.list_users(self.bearer_token())
                    if not self.enforce_subscription_capacity("users", len(users_now)):
                        return
                    user = AUTH.create_user(
                        self.bearer_token(), payload.get("username"),
                        payload.get("password"), payload.get("role"),
                        all_sites=payload.get("all_sites", False),
                        site_ids=payload.get("site_ids", []),
                    )
            except PermissionError as error:
                self.send_json({"error": str(error)}, 403)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event(
                "user.created", target_type="user", target_id=user["id"],
                metadata={"username": user["username"], "role": user["role"]},
            )
            self.send_json({"user": user}, 201)
            return

        user_update = re.fullmatch(r"/api/users/([a-f0-9]{32})/update", path)
        if user_update:
            if not self.require_auth("users.manage"):
                return
            try:
                user = AUTH.update_user(
                    self.bearer_token(), user_update.group(1),
                    role=payload.get("role"),
                    enabled=payload.get("enabled"),
                    password=payload.get("password"),
                    all_sites=payload.get("all_sites"),
                    site_ids=payload.get("site_ids"),
                )
            except PermissionError as error:
                self.send_json({"error": str(error)}, 403)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event(
                "user.updated", target_type="user", target_id=user["id"],
                metadata={"username": user["username"], "role": user["role"],
                          "enabled": user["enabled"], "changed_fields": sorted(payload.keys())},
            )
            self.send_json({"user": user})
            return

        if path == "/api/capture/start":
            try:
                capture = LIVE_CAPTURE.start(
                    interface=payload.get("interface"),
                    duration_seconds=payload.get("duration_seconds", 15),
                    packet_limit=payload.get("packet_limit", 250),
                    filter_profile=payload.get("filter_profile", "all"),
                )
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except RuntimeError as error:
                self.send_json({"error": str(error)}, 409)
                return
            self.audit_event(
                "capture.started", target_type="packet_capture", target_id=capture["capture_id"],
                metadata={
                    "interface": capture["interface"],
                    "duration_seconds": capture["duration_limit_seconds"],
                    "packet_limit": capture["packet_limit"],
                    "filter_profile": capture["filter_profile"],
                },
            )
            self.send_json({"capture": capture}, 201)
            return

        if path == "/api/capture/stop":
            try:
                capture = LIVE_CAPTURE.stop(payload.get("capture_id"))
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except KeyError:
                self.send_json({"error": "Capture not found"}, 404)
                return
            self.audit_event(
                "capture.stopped", target_type="packet_capture", target_id=capture["capture_id"],
                metadata={"state": capture["state"], "captured_bytes": capture["captured_bytes"]},
            )
            self.send_json({"capture": capture})
            return

        if path == "/api/webhooks/subscriptions":
            if not self.require_auth("webhooks.manage"):
                return
            scope = AUTH.site_access(self.bearer_token())
            allowed_sites = None if scope["all_sites"] else scope["site_ids"]
            try:
                with BILLING_QUOTA_LOCK:
                    subscription_count = len(WEBHOOK_SUBSCRIPTIONS.list_subscriptions())
                    if not self.enforce_subscription_capacity("webhook_subscriptions", subscription_count):
                        return
                    subscription = WEBHOOK_SUBSCRIPTIONS.create(
                        payload.get("subscription"),
                        allowed_site_ids=allowed_sites,
                    )
            except PermissionError as error:
                self.send_json({"error": str(error)}, 403)
                return
            except WebhookSubscriptionConflictError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event(
                "webhook.subscription.created",
                target_type="webhook_subscription",
                target_id=subscription["subscription_id"],
                metadata={"enabled": subscription["enabled"], "site_count": len(subscription["site_allowlist"])},
            )
            self.send_json({"subscription": subscription}, 201)
            return

        subscription_probe = re.fullmatch(
            r"/api/webhooks/subscriptions/([A-Za-z0-9][A-Za-z0-9._:-]{0,63})/probe",
            path,
        )
        if subscription_probe:
            if not self.require_auth("webhooks.manage"):
                return
            subscription_id = subscription_probe.group(1)
            scope = AUTH.site_access(self.bearer_token())
            site_filter = None if scope["all_sites"] else scope["site_ids"]
            subscription = WEBHOOK_SUBSCRIPTIONS.get(subscription_id, site_ids=site_filter)
            if subscription is None:
                self.send_json({"error": "Subscription not found"}, 404)
                return
            host = urlparse(subscription["endpoint"]).hostname
            if not host:
                self.send_json({"error": "Saved endpoint does not contain a DNS hostname"}, 400)
                return
            connection = None
            resolved_addresses = []
            try:
                resolved_addresses = _resolve_public_addresses(host)
                resolved_at = datetime.now(timezone.utc)
                for address in resolved_addresses[:4]:
                    try:
                        connection = _PinnedHTTPSConnection(host, address, 3)
                        break
                    except Exception:
                        continue
                if connection is None:
                    self.send_json({
                        "error": "Could not establish a verified TLS connection to the allow-listed endpoint",
                        "code": "tls_connect_failed",
                    }, 503)
                    return
                connected_at = datetime.now(timezone.utc)
                evidence = {
                    "subscription_id": subscription_id,
                    "endpoint": subscription["endpoint"],
                    "allowed_hosts": subscription["allowed_hosts"],
                    "resolution_at": resolved_at.isoformat(),
                    "connected_at": connected_at.isoformat(),
                    "resolved_addresses": resolved_addresses,
                    "peer_ip": connection.peer_ip,
                    "connected_port": connection.connected_port,
                    "tls_version": connection.tls_version,
                    "tls_verified": connection.tls_verified,
                    "hostname_verified": connection.hostname_verified,
                    "redirect_location": None,
                }
                verification_response = run_feature(
                    "router_webhook_egress_policy_verifier", evidence
                )
                verification = verification_response.get("result", {})
                self.audit_event(
                    "webhook.subscription.egress_probed",
                    target_type="webhook_subscription",
                    target_id=subscription_id,
                    metadata={
                        "approved": bool(verification.get("approved")),
                        "tls_version": evidence["tls_version"],
                        "resolved_address_count": len(resolved_addresses),
                    },
                )
                self.send_json({
                    "subscription_id": subscription_id,
                    "approved": bool(verification.get("approved")),
                    "evidence": evidence if verification.get("approved") else None,
                    "verification": verification,
                    "note": "TLS handshake only; no HTTP request was sent to the webhook endpoint.",
                })
            except Exception:
                self.audit_event(
                    "webhook.subscription.egress_probe_failed",
                    target_type="webhook_subscription",
                    target_id=subscription_id,
                    outcome="denied",
                )
                self.send_json({
                    "error": "DNS or pinned TLS verification failed for the configured endpoint",
                    "code": "egress_probe_failed",
                }, 503)
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except OSError:
                        pass
            return

        subscription_update = re.fullmatch(
            r"/api/webhooks/subscriptions/([A-Za-z0-9][A-Za-z0-9._:-]{0,63})/update",
            path,
        )
        if subscription_update:
            if not self.require_auth("webhooks.manage"):
                return
            subscription_id = subscription_update.group(1)
            scope = AUTH.site_access(self.bearer_token())
            allowed_sites = None if scope["all_sites"] else scope["site_ids"]
            try:
                subscription = WEBHOOK_SUBSCRIPTIONS.update(
                    subscription_id,
                    payload.get("subscription"),
                    allowed_site_ids=allowed_sites,
                )
            except PermissionError as error:
                self.send_json({"error": str(error)}, 403)
                return
            except WebhookSubscriptionNotFoundError:
                self.send_json({"error": "Subscription not found"}, 404)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event(
                "webhook.subscription.updated",
                target_type="webhook_subscription",
                target_id=subscription_id,
                metadata={"enabled": subscription["enabled"], "site_count": len(subscription["site_allowlist"])},
            )
            self.send_json({"subscription": subscription})
            return

        subscription_delete = re.fullmatch(
            r"/api/webhooks/subscriptions/([A-Za-z0-9][A-Za-z0-9._:-]{0,63})/delete",
            path,
        )
        if subscription_delete:
            if not self.require_auth("webhooks.manage"):
                return
            subscription_id = subscription_delete.group(1)
            scope = AUTH.site_access(self.bearer_token())
            site_filter = None if scope["all_sites"] else scope["site_ids"]
            try:
                result = WEBHOOK_SUBSCRIPTIONS.delete(subscription_id, site_ids=site_filter)
            except WebhookSubscriptionNotFoundError:
                self.send_json({"error": "Subscription not found"}, 404)
                return
            self.audit_event(
                "webhook.subscription.deleted",
                target_type="webhook_subscription",
                target_id=subscription_id,
            )
            self.send_json(result)
            return

        if path == "/api/webhooks/deliveries/enqueue":
            if not self.require_auth("webhooks.manage"):
                return
            scope = AUTH.site_access(self.bearer_token())
            allowed_sites = None if scope["all_sites"] else scope["site_ids"]
            try:
                result = WEBHOOK_DELIVERIES.enqueue_many(
                    payload.get("deliveries"), now=payload.get("now"),
                    max_attempts=payload.get("max_attempts", 6),
                    allowed_site_ids=allowed_sites,
                )
            except PermissionError as error:
                self.send_json({"error": str(error)}, 403)
                return
            except WebhookDeliveryConflictError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event(
                "webhook.delivery.enqueued", target_type="webhook_delivery_batch",
                metadata={"created_count": result["created_count"], "duplicate_count": result["duplicate_count"]},
            )
            self.send_json(result, 201 if result["created_count"] else 200)
            return

        webhook_action = re.fullmatch(r"/api/webhooks/deliveries/([1-9][0-9]*)/(retry|cancel)", path)
        if webhook_action:
            if not self.require_auth("webhooks.manage"):
                return
            delivery_id = int(webhook_action.group(1))
            delivery = WEBHOOK_DELIVERIES.get(delivery_id)
            if not self.require_webhook_delivery_site_access(delivery):
                return
            try:
                if webhook_action.group(2) == "retry":
                    response = WEBHOOK_DELIVERIES.retry(delivery_id, now=payload.get("now"))
                    action = "webhook.delivery.retried"
                else:
                    response = WEBHOOK_DELIVERIES.cancel(delivery_id, now=payload.get("now"))
                    action = "webhook.delivery.cancelled"
            except WebhookDeliveryNotFoundError:
                self.send_json({"error": "Delivery is not in a retryable or cancellable state"}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event(action, target_type="webhook_delivery", target_id=str(delivery_id),
                             metadata={"status": response["status"]})
            self.send_json({"delivery": response})
            return

        if path == "/api/reports/jobs/enqueue":
            if not self.require_auth("reports.manage"):
                return
            if not self.require_site_access(_collect_site_ids(payload), require_explicit=True):
                return
            try:
                prepared = run_feature("router_scheduled_report_job_intake", payload)["result"]
                if not self.require_site_access(_collect_site_ids(prepared), require_explicit=True):
                    return
                response = REPORT_JOBS.enqueue(prepared)
            except ReportJobConflictError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.send_json(response, 201 if response["created"] else 200)
            return

        if path == "/api/reports/jobs/claim":
            if not self.require_auth("reports.manage"):
                return
            job_scope = AUTH.site_access(self.bearer_token())
            claim_sites = None if job_scope["all_sites"] else job_scope["site_ids"]
            try:
                response = REPORT_JOBS.claim_due(
                    payload.get("worker_id"),
                    now=payload.get("now"),
                    lease_seconds=payload.get("lease_seconds", 120),
                    limit=payload.get("limit", 10),
                    site_ids=claim_sites,
                )
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.send_json(response)
            return

        job_delivery = re.fullmatch(r"/api/reports/jobs/([1-9][0-9]*)/delivery-package", path)
        if job_delivery:
            if not self.require_auth("reports.manage"): 
                return
            try:
                claimed_job = REPORT_JOBS.get_leased_job(
                    int(job_delivery.group(1)),
                    payload.get("lease_id"),
                    now=payload.get("now"),
                )
                if not self.require_report_job_site_access(claimed_job):
                    return
                result = run_feature(
                    "router_scheduled_report_delivery_package",
                    {**payload, "claimed_job": claimed_job},
                )
            except ReportJobNotFoundError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.send_json(result)
            return

        job_action = re.fullmatch(r"/api/reports/jobs/([1-9][0-9]*)/(complete|fail|cancel|renew)", path)
        if job_action:
            if not self.require_auth("reports.manage"): 
                return
            job_id = int(job_action.group(1))
            action = job_action.group(2)
            existing_job = REPORT_JOBS.get(job_id)
            if not self.require_report_job_site_access(existing_job):
                return
            try:
                if action == "renew":
                    response = REPORT_JOBS.renew_lease(
                        job_id,
                        payload.get("lease_id"),
                        now=payload.get("now"),
                        lease_seconds=payload.get("lease_seconds", 120),
                    )
                elif action == "complete":
                    response = REPORT_JOBS.complete(
                        job_id,
                        payload.get("lease_id"),
                        payload.get("result", {}),
                        now=payload.get("now"),
                    )
                elif action == "fail":
                    response = REPORT_JOBS.fail(
                        job_id,
                        payload.get("lease_id"),
                        payload.get("error_code"),
                        now=payload.get("now"),
                    )
                else:
                    response = REPORT_JOBS.cancel(job_id, now=payload.get("now"))
            except ReportJobNotFoundError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.send_json({"job": response})
            return

        if path == "/api/agents/enroll":
            if not self.require_auth("agents.manage"):
                return
            user_site_scope = AUTH.site_access(self.bearer_token())
            requested_site = payload.get("site_id")
            if not self.require_site_access(
                [requested_site] if requested_site is not None else [],
                require_explicit=not user_site_scope["all_sites"],
            ):
                return
            try:
                with BILLING_QUOTA_LOCK:
                    active_agents = sum(
                        1 for item in AGENT_HEALTH.list_agent_credentials()
                        if item["status"] == "active"
                    )
                    if not self.enforce_subscription_capacity("agents", active_agents):
                        return
                    scope = run_feature("router_agent_credential_scope", payload)["result"]
                    negotiation = run_feature("router_agent_negotiation_audit", scope)["result"]
                    credential = AGENT_HEALTH.enroll_agent(
                        agent_id=scope["agent_id"],
                        adapter_id=scope["adapter_id"],
                        agent_version=scope["agent_version"],
                        allowed_capabilities=scope["allowed_capabilities"],
                        ttl_days=payload.get("ttl_days", 90),
                        negotiation=negotiation,
                        site_id=requested_site,
                    )
            except AgentCredentialConflictError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event(
                "agent.credential.enrolled", target_type="agent", target_id=scope["agent_id"],
                metadata={"adapter_id": scope["adapter_id"], "reason_code": "credential_created"},
            )
            self.send_json({"credential": credential}, 201)
            return

        agent_site_update = re.fullmatch(r"/api/agents/([A-Za-z0-9][A-Za-z0-9._:-]{0,63})/site", path)
        if agent_site_update:
            if not self.require_auth("agents.manage"):
                return
            agent_id = agent_site_update.group(1)
            if not self.require_agent_site_access(agent_id):
                return
            target_site = payload.get("site_id")
            user_site_scope = AUTH.site_access(self.bearer_token())
            if target_site is None:
                if not user_site_scope["all_sites"]:
                    self.send_json({"error": "Only all-site administrators may remove an agent's site assignment"}, 403)
                    return
            elif not self.require_site_access([target_site], require_explicit=True):
                return
            try:
                assignment = AGENT_HEALTH.assign_agent_site(agent_id, target_site)
            except ValueError as error:
                self.send_json({"error": str(error)}, 400 if "site_id" in str(error) else 404)
                return
            self.audit_event(
                "agent.site_assignment.updated", target_type="agent", target_id=agent_id,
                metadata={"site_id": target_site},
            )
            self.send_json({"assignment": assignment})
            return

        if path.startswith("/api/agents/") and path.endswith("/credentials/rotate"):
            if not self.require_auth("agents.manage"):
                return
            agent_id = unquote(path[len("/api/agents/"):-len("/credentials/rotate")]).strip("/")
            if not agent_id or "/" in agent_id:
                self.send_json({"error": "Agent not found"}, 404)
                return
            if not self.require_agent_site_access(agent_id):
                return
            try:
                credential = AGENT_HEALTH.rotate_agent_credential(
                    agent_id, ttl_days=payload.get("ttl_days", 90)
                )
            except AgentAuthenticationError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 404 if "not found" in str(error).lower() else 400)
                return
            self.audit_event(
                "agent.credential.rotated", target_type="agent", target_id=agent_id,
                metadata={"reason_code": "credential_rotated"},
            )
            self.send_json({"credential": credential})
            return

        if path.startswith("/api/agents/") and path.endswith("/credentials/revoke"):
            if not self.require_auth("agents.manage"):
                return
            agent_id = unquote(path[len("/api/agents/"):-len("/credentials/revoke")]).strip("/")
            if not agent_id or "/" in agent_id:
                self.send_json({"error": "Agent not found"}, 404)
                return
            if not self.require_agent_site_access(agent_id):
                return
            try:
                result = AGENT_HEALTH.revoke_agent_credential(agent_id)
            except ValueError as error:
                self.send_json({"error": str(error)}, 404)
                return
            self.audit_event(
                "agent.credential.revoked", target_type="agent", target_id=agent_id,
                metadata={"reason_code": "credential_revoked"},
            )
            self.send_json({"credential": result})
            return

        if path == "/api/agents/heartbeat":
            try:
                heartbeat = AGENT_HEALTH.record_heartbeat(payload, token=self.bearer_token())
            except AgentAuthenticationError as error:
                self.send_json({"error": str(error)}, 401)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.send_json({"agent": heartbeat}, 201 if heartbeat["created"] else 200)
            return

        if path == "/api/agents/snapshots/batch":
            try:
                delivery = run_feature("openwrt_snapshot_delivery_envelope", payload)["result"]
                saved = AGENT_HEALTH.record_snapshot(
                    delivery["agent_id"],
                    delivery["snapshot"],
                    token=self.bearer_token(),
                    delivery_id=delivery["delivery_id"],
                )
            except AgentAuthenticationError as error:
                self.send_json({"error": str(error)}, 401)
                return
            except DuplicateAgentDeliveryError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except DuplicateAgentSnapshotError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except Exception as error:
                print(f"[AGENT DELIVERY ERROR] {error}")
                self.send_json({"error": "Agent snapshot delivery failed"}, 500)
                return
            self.send_json({"delivery": saved}, 200 if saved.get("replayed") else 201)
            return

        if path == "/api/agents/snapshot":
            try:
                result = run_feature("openwrt_agent_snapshot_ingest", payload)["result"]
                saved = AGENT_HEALTH.record_snapshot(
                    result["agent_id"], result["snapshot"], token=self.bearer_token()
                )
            except AgentAuthenticationError as error:
                self.send_json({"error": str(error)}, 401)
                return
            except DuplicateAgentSnapshotError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except Exception as error:
                print(f"[AGENT SNAPSHOT ERROR] {error}")
                self.send_json({"error": "Agent snapshot ingestion failed"}, 500)
                return
            self.send_json({"snapshot": saved}, 201)
            return

        if path == "/api/adapters/openwrt/normalise":
            if not self.require_auth("diagnostics.run"): 
                return
            try:
                result = run_feature("openwrt_snapshot_normalizer", payload)
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except Exception as error:
                print(f"[OPENWRT ADAPTER ERROR] {error}")
                self.send_json({"error": "OpenWrt snapshot normalisation failed"}, 500)
                return
            self.send_json(result)
            return

        if path == "/api/adapters/negotiate":
            if not self.require_auth("agents.manage"): 
                return
            try:
                result = run_feature("router_agent_capability_negotiation", payload)
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.send_json(result)
            return

        if path == "/api/sites/audit":
            if not self.require_auth("diagnostics.run"):
                return
            if not self.require_site_access(_collect_site_ids(payload), require_explicit=True):
                return
            try:
                report = run_feature("consolidated_site_audit_report", payload)
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except Exception as error:
                print(f"[SITE AUDIT ERROR] {error}")
                self.send_json({"error": "Site audit failed"}, 500)
                return
            self.send_json(report)
            return

        if path == "/api/sites/history":
            if not self.require_auth("sites.manage"):
                return
            if not self.require_site_access(_collect_site_ids(payload), require_explicit=True):
                return
            try:
                prepared = run_feature("site_discovery_history_snapshot", payload)["result"]
                if not self.require_site_access(_collect_site_ids(prepared), require_explicit=True):
                    return
                saved = HISTORY.record(prepared)
            except DuplicateSnapshotError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except Exception as error:
                print(f"[HISTORY ERROR] {error}")
                self.send_json({"error": "History storage failed"}, 500)
                return
            self.send_json({"snapshot": saved}, 201)
            return

        if path.startswith("/api/features/"):
            if not self.require_auth("diagnostics.run"): 
                return
            slug = unquote(path[len("/api/features/"):]).strip("/")
            scoped_sites = _collect_site_ids(payload)
            if scoped_sites and not self.require_site_access(scoped_sites):
                return
            if not slug or "/" in slug:
                self.send_json({"error": "Unknown feature"}, 404)
                return
            try:
                result = run_feature(slug, payload)
            except KeyError:
                self.send_json({"error": "Unknown feature"}, 404)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except Exception as error:
                print(f"[FEATURE ERROR] {slug}: {error}")
                self.send_json({"error": "Feature execution failed"}, 500)
                return
            self.send_json(result)
            return

        if path.startswith("/api/"):
            if not self.require_auth():
                return
        self.send_json({"error": "Not found"}, 404)


if __name__ == "__main__":
    HOST = os.getenv("WIFI_ANALYZER_HOST", "127.0.0.1")
    PORT = int(os.getenv("WIFI_ANALYZER_PORT", "199"))
    if not 1 <= PORT <= 65535:
        raise SystemExit("WIFI_ANALYZER_PORT must be between 1 and 65535")
    if not os.path.isdir(STATIC_DIR):
        print("[!] No web UI bundle found. Build the frontend or use a release package.")
        print("[*] Starting API-only mode.")
    else:
        print(f"[+] Serving dashboard from {STATIC_DIR}")
    print(f"[+] WiFi Analyzer Pro {APP_VERSION} on http://{HOST}:{PORT}")
    print(f"[+] OS: {OS} | Mode: {'demo' if DEMO_MODE else 'live'}")
    if HOST not in {"127.0.0.1", "localhost", "::1"}:
        print("[SECURITY] The local password gate protects API endpoints. Use a firewall and a VPN/authenticated reverse proxy for remote access.")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down WiFi Analyzer Pro...")
    finally:
        server.server_close()
