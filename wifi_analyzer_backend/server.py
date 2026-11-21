#!/usr/bin/env python3
"""
WiFi Analyzer Pro - All-in-one server
Serves the dashboard UI + API on port 199.
Run:  sudo python3 server.py
Then open:  http://<pi-ip>:199
"""

import sys, os, json, platform, subprocess, re, time, mimetypes, math, hashlib
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime, timezone, timedelta

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
    from .license import (
        LicenseVerificationError, VendorLicenseServiceError, VendorLicenseStore,
        VendorLicenseRenewalWorker,
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
    from .telemetry_store import WiFiTelemetryStore
    from .trusted_ap_store import TrustedAccessPointStore
    from .rf_survey_store import RfSurveyHistoryStore
    from .rf_change_approval_store import RfChangeApprovalStore
    from .regulatory_dataset_store import RegulatoryDatasetStore
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
    from license import (
        LicenseVerificationError, VendorLicenseServiceError, VendorLicenseStore,
        VendorLicenseRenewalWorker,
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
    from telemetry_store import WiFiTelemetryStore
    from trusted_ap_store import TrustedAccessPointStore
    from rf_survey_store import RfSurveyHistoryStore
    from rf_change_approval_store import RfChangeApprovalStore
    from regulatory_dataset_store import RegulatoryDatasetStore
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
TELEMETRY = WiFiTelemetryStore()
TRUSTED_APS = TrustedAccessPointStore()
RF_SURVEYS = RfSurveyHistoryStore()
REGULATORY_DATASETS = RegulatoryDatasetStore()
RF_CHANGE_REQUESTS = RfChangeApprovalStore()
LOCAL_SITE_ID = os.getenv("WIFI_ANALYZER_LOCAL_SITE_ID", "local")
AGENT_HEALTH = RouterAgentHealthStore()
REPORT_JOBS = RouterReportJobStore()
AUDIT = SecurityAuditStore()
LIVE_CAPTURE = LiveCaptureManager()
WEBHOOK_DELIVERIES = WebhookDeliveryStore()
WEBHOOK_SUBSCRIPTIONS = WebhookSubscriptionStore()
LICENSES = VendorLicenseStore()
BILLING = WorkspaceBillingStore(license_store=LICENSES)
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
    """Derive quality/SNR only from valid, measured RSSI and noise values."""
    rssi = net.get("rssi")
    valid_rssi = (
        isinstance(rssi, (int, float))
        and not isinstance(rssi, bool)
        and math.isfinite(rssi)
        and -127 <= rssi <= 0
    )
    net["quality"] = rssi_quality(rssi) if valid_rssi else None
    noise = net.get("noise")
    valid_noise = (
        isinstance(noise, (int, float))
        and not isinstance(noise, bool)
        and math.isfinite(noise)
        and -150 <= noise <= 0
    )
    if valid_rssi and valid_noise:
        net["snr"] = rssi - noise
    elif net.get("snr") is not None:
        snr = net["snr"]
        if not isinstance(snr, (int, float)) or isinstance(snr, bool) or not math.isfinite(snr) or not -20 <= snr <= 150:
            net.pop("snr", None)
    else:
        net.pop("snr", None)
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
    nets = []
    for cell in re.split(r"Cell \d+ -", out)[1:]:
        network = {}
        match = re.search(r'ESSID:"([^"]*)"', cell)
        network["ssid"] = match.group(1) if match else ""
        match = re.search(r"Address: ([0-9A-Fa-f:]{17})", cell)
        network["bssid"] = match.group(1).upper() if match else None
        match = re.search(r"Frequency:([\d.]+)", cell)
        frequency_ghz = float(match.group(1)) if match else None
        frequency_mhz = round(frequency_ghz * 1000) if frequency_ghz is not None else None
        network["frequency"] = frequency_ghz
        match = re.search(r"Channel:(\d+)", cell)
        channel = int(match.group(1)) if match else freq_to_ch(frequency_mhz) if frequency_mhz is not None else None
        network["channel"] = channel or None
        match = re.search(r"Signal level=(-?\d+)", cell)
        network["rssi"] = int(match.group(1)) if match else None
        network["security"] = security_from_ies(cell)
        network["security_detail"] = network["security"]
        network["band"] = frequency_band(frequency_mhz) if frequency_mhz is not None else None
        nets.append(enrich(network))
    return nets

def parse_iw(out):
    nets = []
    blocks = re.split(r"BSS ([0-9a-f:]{17})", out, flags=re.I)
    index = 1
    while index < len(blocks):
        bssid = blocks[index]
        body = blocks[index + 1] if index + 1 < len(blocks) else ""
        index += 2
        network = {"bssid": bssid.upper()}
        match = re.search(r"SSID: (.+)", body)
        network["ssid"] = match.group(1).strip() if match else ""
        match = re.search(r"freq: (\d+)", body)
        frequency_mhz = int(match.group(1)) if match else None
        network["frequency"] = round(frequency_mhz / 1000, 3) if frequency_mhz is not None else None
        match = re.search(r"DS Parameter set: channel (\d+)", body) or re.search(r"\* primary channel: (\d+)", body)
        channel = int(match.group(1)) if match else freq_to_ch(frequency_mhz) if frequency_mhz is not None else None
        network["channel"] = channel or None
        match = re.search(r"signal: (-?[\d.]+) dBm", body)
        network["rssi"] = float(match.group(1)) if match else None
        network["security"] = security_from_ies(body)
        network["security_detail"] = network["security"]
        network["band"] = frequency_band(frequency_mhz) if frequency_mhz is not None else None
        nets.append(enrich(network))
    return nets

def parse_airport(out):
    nets = []
    for line in out.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            rssi = int(parts[2])
        except (ValueError, TypeError):
            rssi = None
        try:
            channel = int(parts[3].split(",")[0])
        except (ValueError, TypeError):
            channel = None
        # airport -s reports a channel but not an unambiguous band/frequency.
        # 2.4/5/6 GHz channel numbers overlap, so do not invent a band mapping.
        security = parts[6] if len(parts) > 6 else "Unknown"
        network = {
            "ssid": parts[0],
            "bssid": parts[1].upper() if re.fullmatch(r"[0-9A-Fa-f:]{17}", parts[1]) else None,
            "rssi": rssi,
            "channel": channel,
            "frequency": None,
            "band": None,
            "security": security,
            "security_detail": security,
        }
        nets.append(enrich(network))
    return nets

def parse_system_profiler(out):
    nets = []
    try:
        data = json.loads(out)
        for interface in data.get("SPAirPortDataType", []):
            for source in interface.get("spairport_airport_other_local_wireless_networks", []):
                channel_text = source.get("spairport_network_channel", "")
                channel_match = re.search(r"\b(\d{1,3})\b", str(channel_text))
                channel = int(channel_match.group(1)) if channel_match else None
                band_match = re.search(r"(2\.4|5|6)\s*GHz", str(channel_text), re.I)
                band = {"2.4": "2.4GHz", "5": "5GHz", "6": "6GHz"}.get(band_match.group(1)) if band_match else None
                frequency_mhz = None
                if channel is not None and band == "2.4GHz" and 1 <= channel <= 14:
                    frequency_mhz = 2484 if channel == 14 else 2407 + 5 * channel
                elif channel is not None and band == "5GHz" and 32 <= channel <= 177:
                    frequency_mhz = 5000 + 5 * channel
                elif channel is not None and band == "6GHz" and 1 <= channel <= 233:
                    frequency_mhz = 5935 if channel == 2 else 5950 + 5 * channel

                signal_noise = str(source.get("spairport_signal_noise", ""))
                signal_match = re.search(r"(-?\d+(?:\.\d+)?)\s*dBm", signal_noise, re.I)
                noise_match = re.search(r"/\s*(-?\d+(?:\.\d+)?)\s*dBm", signal_noise, re.I)
                rssi = float(signal_match.group(1)) if signal_match else None
                noise = float(noise_match.group(1)) if noise_match else None
                bssid = str(source.get("spairport_network_bssid", "")).upper()
                security = source.get("spairport_security_mode") or "Unknown"
                network = {
                    "ssid": source.get("_name", ""),
                    "bssid": bssid if re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", bssid) else None,
                    "rssi": rssi,
                    "noise": noise,
                    "channel": channel,
                    "frequency": round(frequency_mhz / 1000, 3) if frequency_mhz is not None else None,
                    "band": band,
                    "security": security,
                    "security_detail": security,
                }
                nets.append(enrich(network))
    except (TypeError, ValueError, AttributeError):
        return nets
    return nets

def parse_netsh(out):
    nets = []
    for block in re.split(r"(?im)^[ \t]*SSID \d+ :", out)[1:]:
        network = {}
        match = re.search(r"^\s*(.+)", block)
        network["ssid"] = match.group(1).strip() if match else ""
        match = re.search(r"BSSID \d+\s*:\s*([0-9a-f:]{17})", block, re.I)
        network["bssid"] = match.group(1).upper() if match else None
        match = re.search(r"(?im)^[ \t]*Signal[ \t]*:[ \t]*(\d{1,3})[ \t]*%", block)
        signal_pct = int(match.group(1)) if match else None
        network["signal_pct"] = signal_pct if signal_pct is not None and 0 <= signal_pct <= 100 else None
        # netsh reports a percentage, not dBm. Do not turn it into a fabricated RSSI value.
        network["rssi"] = None
        match = re.search(r"Channel\s*:\s*(\d+)", block)
        network["channel"] = int(match.group(1)) if match else None
        match = re.search(r"Band\s*:\s*(2\.4|5|6)\s*GHz", block, re.I)
        if match:
            band_number = match.group(1)
            network["band"] = {"2.4": "2.4GHz", "5": "5GHz", "6": "6GHz"}[band_number]
        else:
            network["band"] = None
        network["frequency"] = None
        match = re.search(r"Authentication\s*:\s*(.+)", block)
        network["security"] = match.group(1).strip() if match else "Unknown"
        network["security_detail"] = network["security"]
        nets.append(enrich(network))
    return nets

def channel_congestion(networks):
    congestion = {"2.4GHz": {}, "5GHz": {}, "6GHz": {}}
    for network in networks:
        raw_channel = network.get("channel")
        if isinstance(raw_channel, bool):
            continue
        try:
            channel = int(raw_channel)
        except (TypeError, ValueError, OverflowError):
            continue
        if channel < 1 or channel > 233 or str(raw_channel).strip() != str(channel):
            continue
        band = network.get("band")
        if band not in {"2.4GHz", "5GHz", "6GHz"}:
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

    def scan_response(self):
        networks = scan()
        sampled_at = time.time()
        interface = get_wifi_iface()
        source = "demo" if DEMO_MODE else "live"
        telemetry_status = "disabled_for_demo" if DEMO_MODE else "stored"
        if not DEMO_MODE and OS == "Linux" and not interface:
            telemetry_status = "unavailable_no_wifi_interface"
        elif not DEMO_MODE:
            try:
                TELEMETRY.record_scan(LOCAL_SITE_ID, networks, sampled_at=sampled_at)
            except Exception:
                telemetry_status = "unavailable"
                print("[TELEMETRY ERROR] Could not persist scan rollup")
        return {
            "networks": networks,
            "congestion": channel_congestion(networks),
            "timestamp": sampled_at,
            "source": source,
            "interface": interface,
            "telemetry": telemetry_status,
        }

    def diagnostics_response(self):
        diagnostics = get_diagnostics()
        if not DEMO_MODE and isinstance(diagnostics, dict):
            try:
                TELEMETRY.record_diagnostics(LOCAL_SITE_ID, diagnostics)
            except Exception:
                print("[TELEMETRY ERROR] Could not persist diagnostic rollup")
        return diagnostics

    def speedtest_response(self):
        result = run_speedtest()
        if not DEMO_MODE and isinstance(result, dict) and not result.get("error"):
            try:
                TELEMETRY.record_speedtest(LOCAL_SITE_ID, result)
            except Exception:
                print("[TELEMETRY ERROR] Could not persist speed-test rollup")
        return result

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

    def managed_site_ids(self):
        site_ids = set(HISTORY.site_ids(limit=100))
        site_ids.update(TELEMETRY.site_ids(limit=100))
        site_ids.update(RF_SURVEYS.site_ids(limit=100))
        site_ids.update(REGULATORY_DATASETS.site_ids(limit=100))
        site_ids.update(RF_CHANGE_REQUESTS.site_ids(limit=100))
        for credential in AGENT_HEALTH.list_agent_credentials():
            site_id = credential.get("site_id")
            if isinstance(site_id, str) and site_id.strip():
                site_ids.add(site_id.strip())
        return sorted(site_ids)

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
            elif path == "/api/sites" or path.startswith("/api/sites/history") or path in {"/api/telemetry/history", "/api/trusted-aps", "/api/sites/rf-surveys", "/api/sites/regulatory-datasets", "/api/sites/rf-change-requests"} or path.startswith("/api/sites/rf-surveys/") or path.startswith("/api/sites/regulatory-datasets/") or path.startswith("/api/sites/rf-change-requests/"):
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
                billing_status = BILLING.status()
                usage = {
                    "users": len(AUTH.list_users(self.bearer_token())),
                    "agents": sum(1 for item in AGENT_HEALTH.list_agent_credentials() if item["status"] == "active"),
                    "webhook_subscriptions": len(WEBHOOK_SUBSCRIPTIONS.list_subscriptions()),
                    "sites": len(self.managed_site_ids()),
                    "feature_runs_monthly": billing_status["monthly_usage"]["feature_runs"],
                }
                billing_status["usage"] = usage
                billing_status["portal_available"] = bool(BILLING.stripe_customer_id())
                billing_status["vendor_checkout_configured"] = bool(
                    LICENSES.configured()
                    and os.getenv("WIFI_ANALYZER_VENDOR_LICENSE_SERVICE_URL", "").strip()
                )
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
            "/api/scan": self.scan_response,
            "/api/system": get_system,
            "/api/phy": get_phy,
            "/api/link": get_link,
            "/api/diagnostics": self.diagnostics_response,
            "/api/has_wifi": has_wifi,
            "/api/devices": lambda: {"devices": get_devices()},
            "/api/speedtest": self.speedtest_response,
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
            elif path == "/api/trusted-aps":
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=2)
                site_values = params.get("site_id", [])
                if len(site_values) != 1 or not site_values[0]:
                    raise ValueError("site_id must be supplied exactly once")
                site_id = site_values[0]
                if not self.require_site_access([site_id], require_explicit=True):
                    return
                records = TRUSTED_APS.list_for_site(site_id)
                self.send_json({
                    "site_id": site_id,
                    "records": records,
                    "record_count": len(records),
                    "can_manage": AUTH.has_permission(self.bearer_token(), "sites.manage"),
                    "privacy": "This is a shared site inventory. SSIDs and BSSIDs are visible to users assigned to this site.",
                })
            elif path == "/api/telemetry/history":
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=5)
                def telemetry_parameter(name):
                    values = params.get(name, [])
                    if len(values) > 1:
                        raise ValueError(f"{name} may be supplied only once")
                    return values[0] if values else None
                try:
                    raw_days = telemetry_parameter("days")
                    raw_limit = telemetry_parameter("limit")
                    days = 7 if raw_days is None else int(raw_days)
                    limit = 5000 if raw_limit is None else int(raw_limit)
                except ValueError as error:
                    raise ValueError("days and limit must be integers") from error
                raw_site_id = telemetry_parameter("site_id")
                scope = AUTH.site_access(self.bearer_token())
                if raw_site_id is not None:
                    if not self.require_site_access([raw_site_id]):
                        return
                    site_filter = [raw_site_id]
                else:
                    site_filter = None if scope["all_sites"] else scope["site_ids"]
                rollups = TELEMETRY.history(site_ids=site_filter, days=days, limit=limit)
                self.send_json({
                    "days": days,
                    "retention_days": TELEMETRY.retention_days,
                    "site_ids": sorted({item["site_id"] for item in rollups}),
                    "rollups": rollups,
                    "privacy": "Minute-level aggregate metrics only; SSIDs, BSSIDs and client identifiers are not retained.",
                })
            elif path == "/api/sites":
                scope = AUTH.site_access(self.bearer_token())
                discovered = set(HISTORY.site_ids(limit=100))
                discovered.update(TELEMETRY.site_ids(limit=100))
                discovered.update(TRUSTED_APS.site_ids(limit=100))
                discovered.update(RF_SURVEYS.site_ids(limit=100))
                discovered.update(REGULATORY_DATASETS.site_ids(limit=100))
                discovered.update(RF_CHANGE_REQUESTS.site_ids(limit=100))
                discovered.update(scope["site_ids"])
                if scope["all_sites"]:
                    discovered.add(LOCAL_SITE_ID)
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
            elif path == "/api/sites/rf-change-requests":
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=3)
                site_values = params.get("site_id", [])
                limit_values = params.get("limit", [])
                if len(site_values) != 1 or not site_values[0].strip():
                    raise ValueError("site_id must be supplied exactly once")
                if len(limit_values) > 1:
                    raise ValueError("limit may be supplied only once")
                try:
                    limit = 50 if not limit_values else int(limit_values[0])
                except ValueError as error:
                    raise ValueError("limit must be an integer") from error
                site_id = site_values[0].strip()
                if not self.require_site_access([site_id], require_explicit=True):
                    return
                requests = RF_CHANGE_REQUESTS.list_for_site(site_id, limit=limit)
                self.send_json({
                    "site_id": site_id,
                    "requests": requests,
                    "request_count": len(requests),
                    "can_manage": AUTH.has_permission(self.bearer_token(), "sites.manage"),
                })
            elif path.startswith("/api/sites/rf-change-requests/"):
                request_id = unquote(path[len("/api/sites/rf-change-requests/"):])
                if not request_id or "/" in request_id:
                    self.send_json({"error": "RF change request not found"}, 404)
                    return
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=2)
                site_values = params.get("site_id", [])
                if len(site_values) != 1 or not site_values[0].strip():
                    raise ValueError("site_id must be supplied exactly once")
                site_id = site_values[0].strip()
                if not self.require_site_access([site_id], require_explicit=True):
                    return
                saved = RF_CHANGE_REQUESTS.get(site_id, request_id, include_packet=True)
                if saved is None:
                    self.send_json({"error": "RF change request not found"}, 404)
                    return
                self.send_json(saved)
            elif path == "/api/sites/rf-surveys":
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=3)
                site_values = params.get("site_id", [])
                limit_values = params.get("limit", [])
                if len(site_values) != 1 or not site_values[0].strip():
                    raise ValueError("site_id must be supplied exactly once")
                if len(limit_values) > 1:
                    raise ValueError("limit may be supplied only once")
                try:
                    limit = 50 if not limit_values else int(limit_values[0])
                except ValueError as error:
                    raise ValueError("limit must be an integer") from error
                site_id = site_values[0].strip()
                if not self.require_site_access([site_id], require_explicit=True):
                    return
                reports = RF_SURVEYS.list_for_site(site_id, limit=limit)
                self.send_json({
                    "site_id": site_id,
                    "reports": reports,
                    "report_count": len(reports),
                    "retention_days": RF_SURVEYS.retention_days,
                    "can_manage": AUTH.has_permission(self.bearer_token(), "sites.manage"),
                    "can_compare": AUTH.has_permission(self.bearer_token(), "diagnostics.run"),
                })
            elif path.startswith("/api/sites/rf-surveys/"):
                survey_id = unquote(path[len("/api/sites/rf-surveys/"):])
                if not survey_id or "/" in survey_id:
                    self.send_json({"error": "RF survey report not found"}, 404)
                    return
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=2)
                site_values = params.get("site_id", [])
                if len(site_values) != 1 or not site_values[0].strip():
                    raise ValueError("site_id must be supplied exactly once")
                site_id = site_values[0].strip()
                if not self.require_site_access([site_id], require_explicit=True):
                    return
                saved = RF_SURVEYS.get(site_id, survey_id)
                if saved is None:
                    self.send_json({"error": "RF survey report not found"}, 404)
                    return
                self.send_json(saved)
            elif path == "/api/sites/regulatory-datasets":
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=4)
                site_values = params.get("site_id", [])
                limit_values = params.get("limit", [])
                revoked_values = params.get("include_revoked", [])
                if len(site_values) != 1 or not site_values[0].strip():
                    raise ValueError("site_id must be supplied exactly once")
                if len(limit_values) > 1 or len(revoked_values) > 1:
                    raise ValueError("limit and include_revoked may be supplied only once")
                try:
                    limit = 50 if not limit_values else int(limit_values[0])
                except ValueError as error:
                    raise ValueError("limit must be an integer") from error
                if revoked_values and revoked_values[0] not in {"true", "false"}:
                    raise ValueError("include_revoked must be true or false")
                include_revoked = not revoked_values or revoked_values[0] == "true"
                site_id = site_values[0].strip()
                if not self.require_site_access([site_id], require_explicit=True):
                    return
                records = REGULATORY_DATASETS.list_for_site(
                    site_id, limit=limit, include_revoked=include_revoked,
                )
                self.send_json({
                    "site_id": site_id,
                    "datasets": records,
                    "dataset_count": len(records),
                    "can_manage": AUTH.has_permission(self.bearer_token(), "sites.manage"),
                })
            elif path.startswith("/api/sites/regulatory-datasets/"):
                dataset_ref = unquote(path[len("/api/sites/regulatory-datasets/"):])
                if not dataset_ref or "/" in dataset_ref:
                    self.send_json({"error": "Regulatory dataset not found"}, 404)
                    return
                params = parse_qs(request_url.query, keep_blank_values=True, max_num_fields=2)
                site_values = params.get("site_id", [])
                if len(site_values) != 1 or not site_values[0].strip():
                    raise ValueError("site_id must be supplied exactly once")
                site_id = site_values[0].strip()
                if not self.require_site_access([site_id], require_explicit=True):
                    return
                retained = REGULATORY_DATASETS.get(site_id, dataset_ref)
                if retained is None:
                    self.send_json({"error": "Regulatory dataset not found"}, 404)
                    return
                if retained["record"]["revoked"]:
                    self.send_json({
                        "error": "Regulatory dataset has been revoked and cannot be used for new planning",
                        "record": retained["record"],
                    }, 410)
                    return
                self.send_json(retained)
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

        if path in {
            "/api/billing/checkout", "/api/billing/portal",
            "/api/license/activate", "/api/license/deactivate",
            "/api/license/checkout", "/api/license/sync", "/api/license/portal",
        }:
            if not self.require_auth("billing.manage"):
                return

        if path == "/api/trusted-aps" and not self.require_auth("sites.manage"):
            return
        if path == "/api/sites/rf-surveys":
            if not self.require_auth("diagnostics.run") or not self.require_auth("sites.manage"):
                return
        if path == "/api/sites/regulatory-datasets" and not self.require_auth("sites.manage"):
            return
        if path == "/api/sites/rf-change-requests":
            if not self.require_auth("diagnostics.run") or not self.require_auth("sites.manage"):
                return
        if path.startswith("/api/sites/rf-change-requests/") and not self.require_auth("sites.manage"):
            return
        if path == "/api/sites/rf-surveys/compare" and not self.require_auth("diagnostics.run"):
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
            "/api/trusted-aps": ("api.trusted_aps.manage", False),
            "/api/sites/rf-surveys": ("api.rf_surveys.manage", False),
            "/api/sites/rf-surveys/compare": ("api.rf_surveys.compare", False),
            "/api/sites/regulatory-datasets": ("api.regulatory_datasets.manage", False),
            "/api/sites/rf-change-requests": ("api.rf_change.create", False),
            "/api/capture/start": ("api.capture.start", False),
            "/api/reports/jobs/enqueue": ("api.report.enqueue", False),
            "/api/webhooks/deliveries/enqueue": ("api.webhook.enqueue", False),
            "/api/billing/checkout": ("api.billing.checkout", False),
            "/api/billing/portal": ("api.billing.portal", False),
            "/api/license/checkout": ("api.license.checkout", False),
            "/api/license/sync": ("api.license.sync", False),
            "/api/license/portal": ("api.license.portal", False),
        }.get(path)
        if rate_policy and not self.enforce_rate_limit(rate_policy[0], client_only=rate_policy[1]):
            return
        if path.startswith("/api/sites/rf-change-requests/") and not self.enforce_rate_limit("api.rf_change.decision"):
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

        if path == "/api/sites/rf-change-requests":
            site_id = payload.get("site_id")
            dataset_ref = payload.get("dataset_ref")
            adapter_id = payload.get("adapter_id")
            radios = payload.get("radios")
            expiry_minutes = payload.get("expiry_minutes", 60)
            if not self.require_site_access([site_id], require_explicit=True):
                return
            if not isinstance(dataset_ref, str) or not dataset_ref.strip():
                self.send_json({"error": "dataset_ref is required"}, 400)
                return
            if isinstance(expiry_minutes, bool) or not isinstance(expiry_minutes, int) or not 1 <= expiry_minutes <= 1440:
                self.send_json({"error": "expiry_minutes must be an integer from 1 to 1440"}, 400)
                return
            adapter = next(
                (item for item in router_adapter_manifests() if item.get("adapter_id") == adapter_id),
                None,
            )
            if adapter is None:
                self.send_json({"error": "adapter_id is not a registered router adapter"}, 400)
                return
            identity = AUTH.identity(self.bearer_token()) or {}
            actor = identity.get("username")
            if not isinstance(actor, str) or not actor:
                self.send_json({"error": "Authenticated requester identity is unavailable"}, 401)
                return
            try:
                radio_json = json.dumps(
                    radios, sort_keys=True, ensure_ascii=False,
                    separators=(",", ":"), allow_nan=False,
                )
            except (TypeError, ValueError):
                self.send_json({"error": "radios must be finite JSON-compatible capability records"}, 400)
                return
            request_fingerprint = hashlib.sha256(json.dumps(
                [site_id, dataset_ref, adapter_id, hashlib.sha256(radio_json.encode("utf-8")).hexdigest()],
                ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")).hexdigest()[:24]
            metadata = {
                "site_id": site_id,
                "request_fingerprint": request_fingerprint,
                "dataset_ref": dataset_ref,
                "adapter_id": adapter_id,
            }
            requested = self.audit_event(
                "rf_change.requested", target_type="rf_change_request",
                target_id=request_fingerprint, metadata=metadata,
            )
            if requested is None:
                self.send_json({"error": "The security audit ledger is unavailable; no change request was created"}, 503)
                return
            meter = None
            try:
                retained = REGULATORY_DATASETS.get(site_id, dataset_ref)
                if retained is None:
                    self.send_json({"error": "Retained regulatory dataset was not found for this site"}, 404)
                    return
                record = retained["record"]
                if record.get("revoked_at") is not None:
                    self.send_json({"error": "Revoked regulatory datasets cannot be used for a change request"}, 409)
                    return
                now = datetime.now(timezone.utc).replace(microsecond=0)
                dataset = retained["dataset"]
                acknowledgement = retained["acknowledgement"]
                planner_input = {
                    "site_id": site_id,
                    "as_of": now.isoformat(),
                    "regulatory_dataset": dataset,
                    "dataset_acknowledgement": acknowledgement,
                    "radios": radios,
                    "maximum_capability_age_days": payload.get("maximum_capability_age_days", 7),
                }
                with BILLING_QUOTA_LOCK:
                    meter = BILLING.consume_monthly_feature_run()
                    if not meter["allowed"]:
                        self.audit_event(
                            "rf_change.rejected", target_type="rf_change_request",
                            target_id=request_fingerprint, outcome="failure", metadata=metadata,
                        )
                        self.send_json({
                            "error": "The monthly diagnostic allowance has been reached",
                            "code": "plan_limit_reached", **meter, "upgrade_required": True,
                        }, 402)
                        return
                    plan = run_feature("radio_capability_regulatory_channel_planner", planner_input)
                    packet = run_feature("rf_change_approval_packet", {
                        "site_id": site_id,
                        "adapter_id": adapter_id,
                        "requested_by": actor,
                        "created_at": now.isoformat(),
                        "expires_at": (now + timedelta(minutes=expiry_minutes)).isoformat(),
                        "required_approvals": 2,
                        "dataset": {
                            "dataset_ref": dataset_ref,
                            "fingerprint_sha256": record["fingerprint_sha256"],
                            "jurisdiction": dataset["jurisdiction"],
                            "dataset_id": dataset["dataset_id"],
                            "version": dataset["version"],
                            "reviewer_id": acknowledgement["reviewer_id"],
                            "review_reference": acknowledgement["review_reference"],
                            "reviewed_at": acknowledgement["reviewed_at"],
                        },
                        "plan": plan["result"],
                        "radios": radios,
                    })
                    created = RF_CHANGE_REQUESTS.create(site_id, packet["result"])
            except ValueError as error:
                if meter and meter.get("allowed"):
                    BILLING.refund_monthly_feature_run(meter["period"])
                self.audit_event(
                    "rf_change.create_failed", target_type="rf_change_request",
                    target_id=request_fingerprint, outcome="failure", metadata=metadata,
                )
                self.send_json({"error": str(error)}, 400)
                return
            except Exception as error:
                if meter and meter.get("allowed"):
                    BILLING.refund_monthly_feature_run(meter["period"])
                self.audit_event(
                    "rf_change.create_failed", target_type="rf_change_request",
                    target_id=request_fingerprint, outcome="failure", metadata=metadata,
                )
                print(f"[RF CHANGE ERROR] {type(error).__name__}: {error}")
                self.send_json({"error": "RF change approval request could not be created"}, 503)
                return
            completed = self.audit_event(
                "rf_change.created", target_type="rf_change_request",
                target_id=created["request_id"],
                metadata={**metadata, "request_id": created["request_id"],
                          "packet_sha256": created["packet_sha256"],
                          "change_count": packet["result"]["packet"]["change_count"]},
            )
            response = {
                "request": created,
                "packet": packet["result"]["packet"],
                "plan": plan["result"],
                "execution_allowed": False,
            }
            if completed is None:
                response["audit_status"] = "request created; outcome audit event could not be persisted"
                self.send_json(response, 202)
            else:
                self.send_json(response, 201)
            return

        if path.startswith("/api/sites/rf-change-requests/"):
            suffix = path[len("/api/sites/rf-change-requests/"):]
            parts = suffix.split("/")
            if len(parts) != 2 or not parts[0] or parts[1] not in {"decision", "cancel", "execute"}:
                self.send_json({"error": "Unknown RF change request action"}, 404)
                return
            request_id, action = unquote(parts[0]), parts[1]
            site_id = payload.get("site_id")
            if not self.require_site_access([site_id], require_explicit=True):
                return
            identity = AUTH.identity(self.bearer_token()) or {}
            actor = identity.get("username")
            if not isinstance(actor, str) or not actor:
                self.send_json({"error": "Authenticated actor identity is unavailable"}, 401)
                return
            current = RF_CHANGE_REQUESTS.get(site_id, request_id, include_packet=True)
            if current is None:
                self.send_json({"error": "RF change request not found"}, 404)
                return
            dataset_ref = current["packet"]["dataset"]["dataset_ref"]
            retained = REGULATORY_DATASETS.get(site_id, dataset_ref)
            if retained is None or retained["record"].get("revoked_at") is not None:
                if current["status"] in {"pending_approval", "approved_not_applied"}:
                    invalidated = RF_CHANGE_REQUESTS.invalidate(
                        site_id, request_id, actor="system",
                        reason="retained regulatory dataset is missing or revoked",
                    )
                else:
                    invalidated = current
                self.audit_event(
                    "rf_change.invalidated", actor=identity,
                    target_type="rf_change_request", target_id=request_id,
                    outcome="failure", metadata={"site_id": site_id, "dataset_ref": dataset_ref},
                )
                self.send_json({
                    "error": "The retained regulatory dataset is missing or revoked; no further approval or deployment is permitted",
                    "request": invalidated,
                }, 409)
                return
            request_fingerprint = hashlib.sha256(json.dumps(
                [site_id, request_id, action, actor], separators=(",", ":"),
            ).encode("utf-8")).hexdigest()[:24]
            metadata = {"site_id": site_id, "request_fingerprint": request_fingerprint}
            requested = self.audit_event(
                "rf_change." + action + "_requested",
                target_type="rf_change_request", target_id=request_id, metadata=metadata,
            )
            if requested is None:
                self.send_json({"error": "The security audit ledger is unavailable; no approval transition was applied"}, 503)
                return
            try:
                if action == "decision":
                    updated = RF_CHANGE_REQUESTS.decide(
                        site_id, request_id, actor=actor,
                        decision=payload.get("decision"), comment=payload.get("comment", ""),
                    )
                elif action == "cancel":
                    updated = RF_CHANGE_REQUESTS.cancel(site_id, request_id, actor=actor)
                else:
                    if current["status"] != "approved_not_applied":
                        self.send_json({
                            "error": "Two independent approvals are required before entering the deployment gate",
                            "request": current,
                        }, 409)
                        return
                    manifest = next(
                        (item for item in router_adapter_manifests()
                         if item.get("adapter_id") == current["adapter_id"]),
                        None,
                    )
                    reason = "no write-capable controller adapter is registered"
                    if manifest is not None and manifest.get("read_only") is not True:
                        reason = "controller adapter lacks the required verified deployment contract"
                    updated = RF_CHANGE_REQUESTS.record_execution_blocked(
                        site_id, request_id, actor=actor, reason=reason,
                    )
                    self.audit_event(
                        "rf_change.execution_blocked", actor=identity,
                        target_type="rf_change_request", target_id=request_id,
                        outcome="failure", metadata={**metadata, "reason": reason},
                    )
                    self.send_json({
                        "error": reason, "code": "write_adapter_unavailable",
                        "request": updated, "applied": False, "execution_allowed": False,
                    }, 409)
                    return
                if updated is None:
                    self.send_json({"error": "RF change request not found"}, 404)
                    return
            except ValueError as error:
                self.audit_event(
                    "rf_change." + action + "_rejected", actor=identity,
                    target_type="rf_change_request", target_id=request_id,
                    outcome="failure", metadata=metadata,
                )
                self.send_json({"error": str(error)}, 400)
                return
            completed_action = (
                "approved" if action == "decision" and payload.get("decision") == "approve"
                else "rejected" if action == "decision"
                else "cancelled"
            )
            completed = self.audit_event(
                "rf_change." + completed_action, actor=identity,
                target_type="rf_change_request", target_id=request_id,
                metadata={**metadata, "status": updated["status"]},
            )
            response = {"request": updated, "execution_allowed": False}
            if completed is None:
                response["audit_status"] = "approval state updated; outcome audit event could not be persisted"
                self.send_json(response, 202)
            else:
                self.send_json(response)
            return

        if path == "/api/sites/rf-surveys/compare":
            site_id = payload.get("site_id")
            baseline_id = payload.get("baseline_report_id")
            current_id = payload.get("current_report_id")
            if not self.require_site_access([site_id], require_explicit=True):
                return
            if not isinstance(baseline_id, str) or not isinstance(current_id, str):
                self.send_json({"error": "baseline_report_id and current_report_id are required"}, 400)
                return
            fingerprint = hashlib.sha256(
                json.dumps([site_id, baseline_id, current_id], separators=(",", ":")).encode("utf-8")
            ).hexdigest()[:24]
            metadata = {"site_id": site_id, "comparison_fingerprint": fingerprint}
            requested = self.audit_event(
                "rf_survey.compare_requested",
                target_type="rf_survey_comparison",
                target_id=fingerprint,
                metadata=metadata,
            )
            if requested is None:
                self.send_json({
                    "error": "The security audit ledger is unavailable; no comparison was run"
                }, 503)
                return
            meter = None
            try:
                baseline = RF_SURVEYS.get(site_id, baseline_id)
                current = RF_SURVEYS.get(site_id, current_id)
                if baseline is None or current is None:
                    self.audit_event(
                        "rf_survey.compare_not_found",
                        target_type="rf_survey_comparison",
                        target_id=fingerprint,
                        outcome="failure",
                        metadata=metadata,
                    )
                    self.send_json({"error": "One or both RF survey reports were not found in this site"}, 404)
                    return
                with BILLING_QUOTA_LOCK:
                    meter = BILLING.consume_monthly_feature_run()
                    if not meter["allowed"]:
                        self.audit_event(
                            "rf_survey.compare_rejected",
                            target_type="rf_survey_comparison",
                            target_id=fingerprint,
                            outcome="failure",
                            metadata=metadata,
                        )
                        self.send_json({
                            "error": "The monthly diagnostic allowance has been reached",
                            "code": "plan_limit_reached",
                            **meter,
                            "upgrade_required": True,
                        }, 402)
                        return
                    try:
                        comparison = run_feature("rf_survey_report_comparator", {
                            "site_id": site_id,
                            "baseline_report": baseline,
                            "current_report": current,
                        })
                    except Exception:
                        BILLING.refund_monthly_feature_run(meter["period"])
                        raise
            except ValueError as error:
                self.audit_event(
                    "rf_survey.compare_failed",
                    target_type="rf_survey_comparison",
                    target_id=fingerprint,
                    outcome="failure",
                    metadata=metadata,
                )
                self.send_json({"error": str(error)}, 400)
                return
            except Exception:
                self.audit_event(
                    "rf_survey.compare_failed",
                    target_type="rf_survey_comparison",
                    target_id=fingerprint,
                    outcome="failure",
                    metadata=metadata,
                )
                print("[RF SURVEY COMPARE ERROR] Could not compare retained survey reports")
                self.send_json({"error": "RF survey comparison failed"}, 503)
                return
            outcome = comparison.get("result", {})
            completed = self.audit_event(
                "rf_survey.compared",
                target_type="rf_survey_comparison",
                target_id=fingerprint,
                metadata={
                    **metadata,
                    "matched_point_count": outcome.get("summary", {}).get("matched_point_count", 0),
                    "comparability": outcome.get("comparability", {}).get("status", "unknown"),
                },
            )
            if completed is None:
                comparison["audit_status"] = "comparison completed; outcome audit event could not be persisted"
                self.send_json(comparison, 202)
            else:
                self.send_json(comparison)
            return

        if path == "/api/sites/regulatory-datasets":
            site_id = payload.get("site_id")
            operation = payload.get("operation", "retain")
            if not self.require_site_access([site_id], require_explicit=True):
                return
            if operation not in {"retain", "revoke"}:
                self.send_json({"error": "operation must be retain or revoke"}, 400)
                return
            if operation == "revoke":
                dataset_ref = payload.get("dataset_ref")
                reason = payload.get("reason")
                if not isinstance(dataset_ref, str) or not dataset_ref:
                    self.send_json({"error": "dataset_ref is required"}, 400)
                    return
                request_fingerprint = hashlib.sha256(
                    json.dumps([site_id, dataset_ref, "revoke"], separators=(",", ":")).encode("utf-8")
                ).hexdigest()[:24]
                metadata = {"site_id": site_id, "dataset_fingerprint": request_fingerprint}
                requested = self.audit_event(
                    "regulatory_dataset.revoke_requested",
                    target_type="regulatory_dataset",
                    target_id=request_fingerprint,
                    metadata=metadata,
                )
                if requested is None:
                    self.send_json({
                        "error": "The security audit ledger is unavailable; no regulatory dataset was revoked"
                    }, 503)
                    return
                try:
                    identity = AUTH.identity(self.bearer_token()) or {}
                    actor = identity.get("username")
                    revoked = REGULATORY_DATASETS.revoke(
                        site_id, dataset_ref, actor=actor, reason=reason,
                    )
                except ValueError as error:
                    self.audit_event(
                        "regulatory_dataset.revoke_rejected",
                        target_type="regulatory_dataset",
                        target_id=request_fingerprint,
                        outcome="failure",
                        metadata=metadata,
                    )
                    self.send_json({"error": str(error)}, 400)
                    return
                if not revoked:
                    self.audit_event(
                        "regulatory_dataset.revoke_not_found",
                        target_type="regulatory_dataset",
                        target_id=request_fingerprint,
                        outcome="failure",
                        metadata=metadata,
                    )
                    self.send_json({"error": "Regulatory dataset not found or already revoked"}, 404)
                    return
                completed = self.audit_event(
                    "regulatory_dataset.revoked",
                    target_type="regulatory_dataset",
                    target_id=request_fingerprint,
                    metadata=metadata,
                )
                response = {"revoked": True, "dataset_ref": dataset_ref}
                if completed is None:
                    response["audit_status"] = "dataset revoked; outcome audit event could not be persisted"
                    self.send_json(response, 202)
                else:
                    self.send_json(response)
                return

            dataset = payload.get("dataset")
            acknowledgement = payload.get("acknowledgement")
            if not isinstance(dataset, dict) or not isinstance(acknowledgement, dict):
                self.send_json({"error": "dataset and acknowledgement objects are required"}, 400)
                return
            if acknowledgement.get("acknowledged") is not True:
                self.send_json({"error": "An explicit operator acknowledgement is required before retaining this dataset"}, 400)
                return
            request_fingerprint = hashlib.sha256(
                json.dumps(
                    [site_id, dataset.get("dataset_id"), dataset.get("version"),
                     dataset.get("dataset_fingerprint_sha256"), "retain"],
                    ensure_ascii=False, separators=(",", ":"), default=str,
                ).encode("utf-8")
            ).hexdigest()[:24]
            metadata = {
                "site_id": site_id,
                "dataset_fingerprint": request_fingerprint,
            }
            requested = self.audit_event(
                "regulatory_dataset.retain_requested",
                target_type="regulatory_dataset",
                target_id=request_fingerprint,
                metadata=metadata,
            )
            if requested is None:
                self.send_json({
                    "error": "The security audit ledger is unavailable; no regulatory dataset was retained"
                }, 503)
                return
            try:
                identity = AUTH.identity(self.bearer_token()) or {}
                reviewer_id = identity.get("username")
                if not reviewer_id:
                    self.send_json({"error": "Authenticated reviewer identity is unavailable"}, 403)
                    return
                acknowledgement = {
                    **acknowledgement,
                    "reviewer_id": reviewer_id,
                    "reviewed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "acknowledged": True,
                }
                retained = REGULATORY_DATASETS.save(site_id, dataset, acknowledgement)
            except ValueError as error:
                self.audit_event(
                    "regulatory_dataset.retain_rejected",
                    target_type="regulatory_dataset",
                    target_id=request_fingerprint,
                    outcome="failure",
                    metadata=metadata,
                )
                self.send_json({"error": str(error)}, 400)
                return
            except Exception:
                self.audit_event(
                    "regulatory_dataset.retain_failed",
                    target_type="regulatory_dataset",
                    target_id=request_fingerprint,
                    outcome="failure",
                    metadata=metadata,
                )
                print("[REGULATORY DATASET ERROR] Could not retain site dataset")
                self.send_json({"error": "Regulatory dataset retention failed"}, 503)
                return
            completed = self.audit_event(
                "regulatory_dataset.retained",
                target_type="regulatory_dataset",
                target_id=retained["dataset_ref"],
                metadata={
                    **metadata,
                    "jurisdiction": retained["jurisdiction"],
                    "dataset_id": retained["dataset_id"],
                    "version": retained["version"],
                },
            )
            response = {"record": retained, "created": retained["created"]}
            if completed is None:
                response["audit_status"] = "dataset retained; outcome audit event could not be persisted"
                self.send_json(response, 202)
            else:
                self.send_json(response, 201 if retained["created"] else 200)
            return

        if path == "/api/sites/rf-surveys" and payload.get("operation") == "delete":
            site_id = payload.get("site_id")
            survey_id = payload.get("survey_id")
            if not self.require_site_access([site_id], require_explicit=True):
                return
            if not isinstance(survey_id, str) or not survey_id:
                self.send_json({"error": "survey_id is required"}, 400)
                return
            fingerprint = hashlib.sha256(
                (str(site_id) + "\\0" + survey_id).encode("utf-8")
            ).hexdigest()[:24]
            metadata = {"site_id": site_id, "report_fingerprint": fingerprint}
            requested = self.audit_event(
                "rf_survey.delete_requested",
                target_type="rf_survey_report",
                target_id=fingerprint,
                metadata=metadata,
            )
            if requested is None:
                self.send_json({
                    "error": "The security audit ledger is unavailable; no report was deleted"
                }, 503)
                return
            try:
                deleted = RF_SURVEYS.delete(site_id, survey_id)
            except ValueError as error:
                self.audit_event(
                    "rf_survey.delete_rejected",
                    target_type="rf_survey_report",
                    target_id=fingerprint,
                    outcome="failure",
                    metadata=metadata,
                )
                self.send_json({"error": str(error)}, 400)
                return
            if deleted:
                completed = self.audit_event(
                    "rf_survey.deleted",
                    target_type="rf_survey_report",
                    target_id=fingerprint,
                    metadata=metadata,
                )
                if completed is None:
                    self.send_json({
                        "deleted": True,
                        "audit_status": "report deleted; outcome audit event could not be persisted",
                    }, 202)
                    return
            else:
                self.audit_event(
                    "rf_survey.delete_not_found",
                    target_type="rf_survey_report",
                    target_id=fingerprint,
                    outcome="failure",
                    metadata=metadata,
                )
            self.send_json({"deleted": deleted})
            return

        if path == "/api/sites/rf-surveys":
            site_id = payload.get("site_id")
            survey_payload = payload.get("survey")
            label = payload.get("label")
            if not self.require_site_access([site_id], require_explicit=True):
                return
            if not isinstance(survey_payload, dict) or survey_payload.get("site_id") != site_id:
                self.send_json({"error": "survey.site_id must match the requested site_id"}, 400)
                return

            request_fingerprint = hashlib.sha256(
                (str(site_id) + ":" + str(time.time_ns())).encode("utf-8")
            ).hexdigest()[:24]
            audit_metadata = {
                "site_id": site_id,
                "request_fingerprint": request_fingerprint,
            }
            requested = self.audit_event(
                "rf_survey.save_requested",
                target_type="rf_survey_report",
                target_id=request_fingerprint,
                metadata=audit_metadata,
            )
            if requested is None:
                self.send_json({
                    "error": "The security audit ledger is unavailable; no report was saved"
                }, 503)
                return

            meter = None
            charged = False
            try:
                with BILLING_QUOTA_LOCK:
                    known_sites = self.managed_site_ids()
                    if site_id not in known_sites and not self.enforce_subscription_capacity(
                        "sites", len(known_sites)
                    ):
                        return
                    meter = BILLING.consume_monthly_feature_run()
                    if not meter["allowed"]:
                        self.audit_event(
                            "rf_survey.save_rejected",
                            target_type="rf_survey_report",
                            target_id=request_fingerprint,
                            outcome="failure",
                            metadata=audit_metadata,
                        )
                        self.send_json({
                            "error": "The monthly diagnostic allowance has been reached",
                            "code": "plan_limit_reached",
                            **meter,
                            "upgrade_required": True,
                        }, 402)
                        return
                    charged = True
                    analysis = run_feature("floorplan_rf_survey_analyzer", survey_payload)
                    saved = RF_SURVEYS.save(site_id, analysis["result"], label=label)
            except ValueError as error:
                if charged and meter:
                    BILLING.refund_monthly_feature_run(meter["period"])
                self.audit_event(
                    "rf_survey.save_failed",
                    target_type="rf_survey_report",
                    target_id=request_fingerprint,
                    outcome="failure",
                    metadata=audit_metadata,
                )
                self.send_json({"error": str(error)}, 400)
                return
            except Exception:
                if charged and meter:
                    BILLING.refund_monthly_feature_run(meter["period"])
                self.audit_event(
                    "rf_survey.save_failed",
                    target_type="rf_survey_report",
                    target_id=request_fingerprint,
                    outcome="failure",
                    metadata=audit_metadata,
                )
                print("[RF SURVEY ERROR] Could not validate or persist survey report")
                self.send_json({"error": "RF survey report storage failed"}, 503)
                return

            completed = self.audit_event(
                "rf_survey.saved",
                target_type="rf_survey_report",
                target_id=saved["survey_id"],
                metadata={
                    **audit_metadata,
                    "floorplan_id": saved["floorplan_id"],
                    "measurement_count": saved["measurement_count"],
                },
            )
            response = {
                "feature": "F203",
                "report": saved,
                "result": analysis["result"],
            }
            if completed is None:
                response["audit_status"] = (
                    "report saved; outcome audit event could not be persisted"
                )
                self.send_json(response, 202)
            else:
                self.send_json(response, 201)
            return

        if path == "/api/trusted-aps":
            site_id = payload.get("site_id")
            ssid = payload.get("ssid")
            bssid = payload.get("bssid")
            operation = payload.get("operation")
            if not self.require_site_access([site_id], require_explicit=True):
                return
            fingerprint = hashlib.sha256(
                json.dumps([site_id, ssid, bssid], ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")
            ).hexdigest()[:24]
            audit_metadata = {"entry_fingerprint": fingerprint, "operation": str(operation)}
            requested = self.audit_event(
                "trusted_ap.change_requested",
                target_type="trusted_ap_baseline",
                target_id=fingerprint,
                metadata=audit_metadata,
            )
            if requested is None:
                self.send_json({"error": "The security audit ledger is unavailable; no baseline change was applied"}, 503)
                return
            try:
                if operation == "add":
                    outcome = TRUSTED_APS.add(site_id, ssid, bssid)
                    if outcome["created"]:
                        confirmed = self.audit_event(
                            "trusted_ap.added",
                            target_type="trusted_ap_baseline",
                            target_id=fingerprint,
                            metadata=audit_metadata,
                        )
                        if confirmed is None:
                            self.send_json({
                                "site_id": site_id,
                                "created": True,
                                "record": outcome["record"],
                                "audit_status": "request recorded; final outcome event could not be persisted",
                            }, 202)
                            return
                    self.send_json({
                        "site_id": site_id,
                        "created": outcome["created"],
                        "record": outcome["record"],
                    }, 201 if outcome["created"] else 200)
                    return
                if operation == "remove":
                    removed = TRUSTED_APS.remove(site_id, ssid, bssid)
                    if removed:
                        confirmed = self.audit_event(
                            "trusted_ap.removed",
                            target_type="trusted_ap_baseline",
                            target_id=fingerprint,
                            metadata=audit_metadata,
                        )
                        if confirmed is None:
                            self.send_json({
                                "site_id": site_id,
                                "removed": True,
                                "audit_status": "request recorded; final outcome event could not be persisted",
                            }, 202)
                            return
                    self.send_json({"site_id": site_id, "removed": removed})
                    return
                raise ValueError("operation must be add or remove")
            except ValueError as error:
                self.audit_event(
                    "trusted_ap.change_rejected",
                    target_type="trusted_ap_baseline",
                    target_id=fingerprint,
                    outcome="failure",
                    metadata=audit_metadata,
                )
                self.send_json({"error": str(error)}, 400)
                return
            except Exception:
                self.audit_event(
                    "trusted_ap.change_failed",
                    target_type="trusted_ap_baseline",
                    target_id=fingerprint,
                    outcome="failure",
                    metadata=audit_metadata,
                )
                print("[TRUSTED AP ERROR] Could not update site baseline")
                self.send_json({"error": "Trusted AP baseline update failed"}, 503)
                return

        if path == "/api/license/checkout":
            service_url = os.getenv("WIFI_ANALYZER_VENDOR_LICENSE_SERVICE_URL", "").strip()
            if not service_url:
                self.send_json({"error": "The vendor licensing service URL is not configured on this installation"}, 503)
                return
            try:
                checkout = LICENSES.start_checkout(
                    service_url=service_url,
                    installation_id=BILLING.instance_id(),
                    plan_id=payload.get("plan_id"),
                    customer_email=payload.get("customer_email"),
                )
            except LicenseVerificationError as error:
                self.send_json({"error": str(error)}, 503)
                return
            except VendorLicenseServiceError as error:
                self.send_json({"error": str(error)}, 502)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event(
                "license.checkout.created",
                target_type="product_license",
                target_id=checkout["license_id"],
                metadata={"plan_id": checkout["plan_id"]},
            )
            self.send_json({"checkout": checkout}, 201)
            return

        if path == "/api/license/sync":
            try:
                synced = LICENSES.sync_from_vendor(
                    installation_id=BILLING.instance_id(),
                )
            except VendorLicenseServiceError as error:
                self.send_json({"error": str(error)}, 502)
                return
            except LicenseVerificationError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event(
                "license.synced",
                target_type="product_license",
                target_id=synced["license_id"],
                metadata={"plan_id": synced["plan_id"]},
            )
            self.send_json({"license": synced})
            return

        if path == "/api/license/portal":
            try:
                portal = LICENSES.open_vendor_portal(
                    installation_id=BILLING.instance_id(),
                )
            except VendorLicenseServiceError as error:
                self.send_json({"error": str(error)}, 502)
                return
            except LicenseVerificationError as error:
                self.send_json({"error": str(error)}, 409)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event("license.portal.opened", target_type="product_license")
            self.send_json({"portal": portal})
            return

        if path == "/api/license/activate":
            try:
                activated = LICENSES.activate(
                    payload.get("license_token"),
                    BILLING.instance_id(),
                )
            except LicenseVerificationError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            self.audit_event(
                "license.activated",
                target_type="product_license",
                target_id=activated["license_id"],
                metadata={"plan_id": activated["plan_id"]},
            )
            self.send_json({"license": activated})
            return

        if path == "/api/license/deactivate":
            removed = LICENSES.deactivate()
            self.audit_event(
                "license.deactivated",
                target_type="product_license",
                metadata={"removed": removed},
            )
            self.send_json({"removed": removed, "billing": BILLING.status()})
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
                    if requested_site is not None:
                        known_sites = self.managed_site_ids()
                        if requested_site not in known_sites and not self.enforce_subscription_capacity("sites", len(known_sites)):
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
                with BILLING_QUOTA_LOCK:
                    if target_site is not None:
                        known_sites = self.managed_site_ids()
                        if target_site not in known_sites and not self.enforce_subscription_capacity("sites", len(known_sites)):
                            return
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
                with BILLING_QUOTA_LOCK:
                    meter = BILLING.consume_monthly_feature_run()
                    if not meter["allowed"]:
                        self.send_json({
                            "error": "The monthly diagnostic allowance has been reached",
                            "code": "plan_limit_reached",
                            **meter,
                            "upgrade_required": True,
                        }, 402)
                        return
                    try:
                        report = run_feature("consolidated_site_audit_report", payload)
                    except Exception:
                        BILLING.refund_monthly_feature_run(meter["period"])
                        raise
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
                with BILLING_QUOTA_LOCK:
                    known_sites = self.managed_site_ids()
                    prepared_site = prepared.get("site_id")
                    if prepared_site not in known_sites and not self.enforce_subscription_capacity("sites", len(known_sites)):
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
            registry_dataset_ref = None
            if slug == "radio_capability_regulatory_channel_planner":
                site_id = payload.get("site_id")
                registry_dataset_ref = payload.get("regulatory_dataset_ref")
                if not isinstance(site_id, str) or not site_id.strip():
                    self.send_json({"error": "site_id is required for radio capability planning"}, 400)
                    return
                if not self.require_site_access([site_id], require_explicit=True):
                    return
                if not isinstance(registry_dataset_ref, str) or not registry_dataset_ref.strip():
                    self.send_json({
                        "error": "A retained regulatory_dataset_ref is required; inline regulatory JSON is not accepted by the production API"
                    }, 400)
                    return
                if "regulatory_dataset" in payload or "dataset_acknowledgement" in payload:
                    self.send_json({
                        "error": "When using regulatory_dataset_ref, dataset contents and acknowledgement are loaded from the protected site registry"
                    }, 400)
                    return
                retained_dataset = REGULATORY_DATASETS.get(site_id, registry_dataset_ref)
                if retained_dataset is None:
                    self.send_json({"error": "Retained regulatory dataset not found in this site"}, 404)
                    return
                if retained_dataset["record"]["revoked"]:
                    self.send_json({
                        "error": "Regulatory dataset has been revoked and cannot be used for new planning",
                        "dataset_ref": registry_dataset_ref,
                    }, 410)
                    return
                payload = {
                    **payload,
                    "regulatory_dataset": retained_dataset["dataset"],
                    "dataset_acknowledgement": retained_dataset["acknowledgement"],
                }

            if slug == "rf_survey_acceptance_auditor":
                site_id = payload.get("site_id")
                survey_id = payload.get("survey_id")
                if "report" in payload:
                    self.send_json({
                        "error": "Submit a saved survey_id; report contents are loaded from protected site history"
                    }, 400)
                    return
                if not isinstance(site_id, str) or not site_id.strip():
                    self.send_json({"error": "site_id is required"}, 400)
                    return
                if not isinstance(survey_id, str) or not survey_id.strip():
                    self.send_json({"error": "survey_id is required"}, 400)
                    return
                if not self.require_site_access([site_id], require_explicit=True):
                    return
                saved_report = RF_SURVEYS.get(site_id, survey_id)
                if saved_report is None:
                    self.send_json({"error": "Saved RF survey report not found in this site"}, 404)
                    return
                payload = {
                    **payload,
                    "report": saved_report,
                }

            if not slug or "/" in slug:
                self.send_json({"error": "Unknown feature"}, 404)
                return
            if slug not in {item["slug"] for item in feature_catalog()}:
                self.send_json({"error": "Unknown feature"}, 404)
                return
            try:
                with BILLING_QUOTA_LOCK:
                    meter = BILLING.consume_monthly_feature_run()
                    if not meter["allowed"]:
                        self.send_json({
                            "error": "The monthly diagnostic allowance has been reached",
                            "code": "plan_limit_reached",
                            **meter,
                            "upgrade_required": True,
                        }, 402)
                        return
                    try:
                        result = run_feature(slug, payload)
                    except Exception:
                        BILLING.refund_monthly_feature_run(meter["period"])
                        raise
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
                return
            except Exception as error:
                print(f"[FEATURE ERROR] {slug}: {error}")
                self.send_json({"error": "Feature execution failed"}, 500)
                return
            if registry_dataset_ref is not None:
                result["result"]["regulatory_dataset_ref"] = registry_dataset_ref
                result["result"]["regulatory_dataset_registry_status"] = "retained_and_not_revoked"
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
    renewal_worker = None
    if LICENSES.configured():
        try:
            renewal_interval = int(os.getenv("WIFI_ANALYZER_VENDOR_LICENSE_RENEW_INTERVAL_SECONDS", "900"))
            renewal_window = int(os.getenv("WIFI_ANALYZER_VENDOR_LICENSE_RENEW_WINDOW_SECONDS", "43200"))
            renewal_worker = VendorLicenseRenewalWorker(
                LICENSES,
                BILLING.instance_id(),
                check_interval_seconds=renewal_interval,
                renewal_window_seconds=renewal_window,
            )
            renewal_worker.start()
        except (TypeError, ValueError) as error:
            server.server_close()
            raise SystemExit(f"Vendor licence renewal configuration is invalid: {error}") from error
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down WiFi Analyzer Pro...")
    finally:
        if renewal_worker is not None:
            renewal_worker.stop()
        server.server_close()
