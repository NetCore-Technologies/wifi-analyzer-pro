"""Harden the Python service before local, container or frozen-binary deployment.

The patch is intentionally guarded: if upstream code has drifted, it exits without
writing server.py. Review the diff after running it.
"""
from pathlib import Path

path = Path("wifi_analyzer_backend/server.py")
source = path.read_text(encoding="utf-8")
changes = []


def replace_once(old: str, new: str, label: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"Expected one match for {label}, found {count}; no files changed.")
    source = source.replace(old, new, 1)
    changes.append(label)


old_imports = '''import sys, os, json, platform, subprocess, re, time, threading, mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# ── Auto-install dependencies ────────────────────────────────────────────────
def pip_install(pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "--quiet"])

OS = platform.system()
for pkg in (["psutil"] + (["pywifi", "comtypes"] if OS == "Windows" else [])):
    try:
        __import__(pkg.replace("-","_"))
    except ImportError:
        print(f"[*] Installing {pkg}...")
        pip_install(pkg)

import psutil
'''
new_imports = '''import sys, os, json, platform, subprocess, re, time, mimetypes
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote

# Runtime dependencies must be installed by the installer or bundled by PyInstaller.
# Never mutate the user's Python environment when the application starts.
import psutil

OS = platform.system()
APP_VERSION = "1.0.7"
DEMO_MODE = os.getenv("WIFI_ANALYZER_DEMO", "").strip().lower() in {"1", "true", "yes", "on"}
DEFAULT_CORS_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}
CORS_ORIGINS = {
    origin.strip()
    for origin in os.getenv("WIFI_ANALYZER_CORS_ORIGINS", "").split(",")
    if origin.strip()
} or DEFAULT_CORS_ORIGINS
'''
replace_once(old_imports, new_imports, "replace runtime dependency installer and HTTP imports")

old_frequency = '''def freq_to_ch(f):
    if f==2484: return 14
    if 2412<=f<=2472: return (f-2407)//5
    if 5180<=f<=5825: return (f-5000)//5
    return 0

def ch_to_freq(ch):
    if ch==14: return 2484
    if 1<=ch<=13: return 2407+ch*5
    if 36<=ch<=165: return 5000+ch*5
    return 2412
'''
new_frequency = '''def freq_to_ch(f):
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
    if "WPA:" in upper or re.search(r"\bWPA\b", upper):
        return "WPA"
    if "PRIVACY" in upper or "ENCRYPTION KEY:ON" in upper:
        return "WEP"
    return "Open"
'''
replace_once(old_frequency, new_frequency, "extend channel mapping and security parsing")

old_enrich = '''def enrich(net):
    net.setdefault("noise",-95)
    net["snr"] = net["rssi"] - net["noise"]
    net["rsrp"] = net["rssi"]
    net["rsrq"] = max(-20, min(0, net["snr"]//3))
    net["sinr"] = net["snr"] - 3
    net["link_speed"] = link_speed(net["rssi"], net["band"])
    net["quality"] = rssi_quality(net["rssi"])
    return net
'''
new_enrich = '''def enrich(net):
    """Calculate signal-to-noise only when a real noise measurement exists."""
    net["quality"] = rssi_quality(net["rssi"])
    if net.get("noise") is not None:
        net["snr"] = net["rssi"] - net["noise"]
    return net
'''
replace_once(old_enrich, new_enrich, "remove fabricated signal/noise and estimated link-rate fields")

old_scan = '''def scan():
    if OS == "Linux":
        iface = get_wifi_iface()
        if not iface: return mock_networks()
        for cmd, parser in [
            (["iwlist", iface, "scan"], parse_iwlist),
            (["iw", iface, "scan"], parse_iw),
        ]:
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10).decode("utf-8","ignore")
                nets = parser(out)
                if nets: return nets
            except: pass
        return mock_networks()
    elif OS == "Darwin":
        paths = ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport","/usr/sbin/airport"]
        for p in paths:
            if os.path.exists(p):
                try:
                    out = subprocess.check_output([p,"-s"], stderr=subprocess.DEVNULL, timeout=10).decode("utf-8","ignore")
                    return parse_airport(out) or mock_networks()
                except: pass
        return mock_networks()
    elif OS == "Windows":
        try:
            out = subprocess.check_output(["netsh","wlan","show","networks","mode=bssid"], stderr=subprocess.DEVNULL, timeout=10).decode("utf-8","ignore")
            return parse_netsh(out) or mock_networks()
        except: return mock_networks()
    return mock_networks()
'''
new_scan = '''def scan():
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
'''
replace_once(old_scan, new_scan, "make demo scans explicit and stop fabricating live access points")

# Keep band identity accurate when an OS scan reports a 6 GHz centre frequency.
source = source.replace('n["band"]="5GHz" if n["frequency"]>3.0 else "2.4GHz"', 'n["band"]=frequency_band(n["frequency"] * 1000)')
source = source.replace('n["band"]="5GHz" if fmhz>3000 else "2.4GHz"', 'n["band"]=frequency_band(fmhz)')

old_congestion = '''def channel_congestion(networks):
    c24,c5={},{}
    for n in networks:
        ch=n.get("channel",0); band=n.get("band","2.4GHz")
        if band=="2.4GHz":
            for adj in range(max(1,ch-2),min(13,ch+3)): c24[adj]=c24.get(adj,0)+1
        else: c5[ch]=c5.get(ch,0)+1
    return {"2.4GHz":c24,"5GHz":c5}
'''
new_congestion = '''def channel_congestion(networks):
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
'''
replace_once(old_congestion, new_congestion, "separate 2.4, 5 and 6 GHz congestion")

# Detect modern security modes from the information elements exposed by the OS.
replace_once(
    'n["security"]="WPA2" if re.search(r"Encryption key:on",cell) else "Open"',
    'n["security"]=security_from_ies(cell)',
    "recognise WPA3 and transition security in iwlist output",
)
replace_once(
    'n["security"]="WPA2" if "WPA2" in body else ("WPA" if "WPA" in body else "Open")',
    'n["security"]=security_from_ies(body)',
    "recognise WPA3 and transition security in iw output",
)

# These fields were plausible-looking demo defaults, not observations from the host.
old_phy_defaults = '''    info.setdefault("tx_bitrate_mbps",433.3); info.setdefault("rx_bitrate_mbps",390.0)
    info.setdefault("mcs_index",9); info.setdefault("channel_width_mhz",80)
    info.setdefault("frequency_mhz",5240); info.setdefault("tx_power_dbm",20.0)
    info.setdefault("phy_mode","802.11ac"); info.setdefault("spatial_streams","2x2")
    info.setdefault("guard_interval","Short (400ns)"); info.setdefault("short_preamble",True)
    info.setdefault("ht_support",True); info.setdefault("vht_support",True)
    info.setdefault("he_support",False); info.setdefault("dfs_support",True)
    info.setdefault("supported_bands",["2.4GHz","5GHz"])
    info.setdefault("beacon_interval_ms",100); info.setdefault("dtim_interval",1)
    info.setdefault("wmm_support",True); info.setdefault("ieee80211k",True)
    info.setdefault("ieee80211v",True); info.setdefault("ieee80211r",False)
'''
replace_once(old_phy_defaults, "", "remove fabricated PHY defaults")

old_link_defaults = '''    stats.setdefault("tx_packets",182340); stats.setdefault("rx_packets",310245)
    stats.setdefault("tx_bytes",24500000); stats.setdefault("rx_bytes",185000000)
    stats.setdefault("tx_errors",12); stats.setdefault("rx_errors",3)
    stats.setdefault("tx_dropped",5); stats.setdefault("rx_dropped",2)
    stats.setdefault("tx_retries",847); stats.setdefault("tx_failed",23)
    stats.setdefault("missed_beacons",4); stats.setdefault("invalid_misc",0)
    stats.setdefault("link_quality",68); stats.setdefault("link_quality_max",70)
'''
replace_once(old_link_defaults, "", "remove fabricated interface counters")

old_diag_defaults = '''    diag.setdefault("latency_ms",4.2); diag.setdefault("jitter_ms",0.8)
    diag.setdefault("packet_loss_pct",0); diag.setdefault("dns_resolution_ms",12.5)
    diag.setdefault("local_ip","192.168.1.100"); diag.setdefault("subnet_mask","255.255.255.0")
    diag.setdefault("dns_servers",["8.8.8.8","8.8.4.4"]); diag.setdefault("mtu",1500)
    diag.setdefault("route_hops",7)
'''
replace_once(old_diag_defaults, "", "remove fabricated diagnostic results")
replace_once('diag["gateway"]=gw or "192.168.1.1"', 'diag["gateway"] = gw', "stop inventing a default gateway")

# The first get_system implementation returns the detailed psutil sample expected by the UI.
old_override = '''_get_system_orig = get_system
def get_system():
    info={"os":OS,"os_version":platform.version(),"hostname":platform.node(),
          "cpu_percent":psutil.cpu_percent(interval=0.1),"memory_percent":psutil.virtual_memory().percent}
    try:
        iface=get_wifi_iface()
        if iface:
            for addr in psutil.net_if_addrs().get(iface,[]):
                if str(addr.family) in ("AddressFamily.AF_INET","2"):
                    info["ip_address"]=addr.address; break
            s=psutil.net_if_stats().get(iface)
            if s: info["wifi_interface"]=iface; info["interface_up"]=s.isup
    except: pass
    return info
'''
replace_once(old_override, "", "restore detailed live system telemetry")

old_static = '''# ── Static file serving ───────────────────────────────────────────────────────
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")

def serve_static(handler, path):
    if path == "/" or not os.path.exists(os.path.join(STATIC_DIR, path.lstrip("/"))):
        filepath = os.path.join(STATIC_DIR, "index.html")
    else:
        filepath = os.path.join(STATIC_DIR, path.lstrip("/"))
    if not os.path.isfile(filepath):
        handler.send_response(404); handler.end_headers(); handler.wfile.write(b"Not found"); return
    mime, _ = mimetypes.guess_type(filepath)
    mime = mime or "application/octet-stream"
    with open(filepath, "rb") as f: data = f.read()
    handler.send_response(200)
    handler.send_header("Content-Type", mime)
    handler.send_header("Content-Length", len(data))
    handler.end_headers()
    handler.wfile.write(data)

# ── HTTP Handler ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): print(f"  {args[0]} {args[1]}")
    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",len(body))
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
        self.end_headers(); self.wfile.write(body)
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
        self.end_headers()
    def do_GET(self):
        path = urlparse(self.path).path
        api_routes = {
            "/api/scan": lambda: (lambda n: {"networks":n,"congestion":channel_congestion(n),"timestamp":time.time()})(scan()),
            "/api/system": get_system,
            "/api/phy": get_phy,
            "/api/link": get_link,
            "/api/diagnostics": get_diagnostics,
            "/api/has_wifi": lambda: has_wifi(),
            "/api/devices": lambda: {"devices": get_devices()},
            "/api/speedtest": lambda: run_speedtest(),
            "/health": lambda: {"status":"ok","os":OS},
        }
        if path in api_routes: self.send_json(api_routes[path]())
        else: serve_static(self, path)
'''
new_static = '''# ── Static file serving ───────────────────────────────────────────────────────
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
class Handler(BaseHTTPRequestHandler):
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

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.add_common_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        self.send_response(204)
        if origin in CORS_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Vary", "Origin")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        api_routes = {
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
            "/api/capabilities": lambda: {
                "name": "WiFi Analyzer Pro",
                "version": APP_VERSION,
                "platform": OS,
                "mode": "demo" if DEMO_MODE else "live",
                "wifi_interface": get_wifi_iface(),
                "features": {"wireless_scan": True, "channel_analysis": True, "device_discovery": True, "speed_test": True},
                "security": {"authentication": False, "remote_access": "Use a VPN or authenticated reverse proxy"},
            },
            "/health": lambda: {"status": "ok", "version": APP_VERSION, "os": OS, "mode": "demo" if DEMO_MODE else "live"},
        }
        try:
            if path in api_routes:
                self.send_json(api_routes[path]())
            elif path.startswith("/api/"):
                self.send_json({"error": "Not found"}, 404)
            else:
                serve_static(self, path)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as error:
            print(f"[ERROR] {path}: {error}")
            if not self.wfile.closed:
                self.send_json({"error": "Internal server error"}, 500)
'''
replace_once(old_static, new_static, "harden static serving, CORS, API routes and request handling")

old_main = '''if __name__ == "__main__":
    PORT = 199
    if not os.path.isdir(STATIC_DIR):
        print(f"[!] No 'dist/' folder found. Run: bash setup.sh first.")
        print(f"[*] Starting API-only mode on port {PORT}...")
    else:
        print(f"[✓] Serving dashboard from dist/")
    print(f"[✓] WiFi Analyzer Pro on http://0.0.0.0:{PORT}")
    print(f"[✓] OS: {OS}")
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
'''
new_main = '''if __name__ == "__main__":
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
        print("[SECURITY] API authentication is not built in. Use only on a trusted LAN or behind a VPN/authenticated reverse proxy.")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\\n[+] Shutting down WiFi Analyzer Pro...")
    finally:
        server.server_close()
'''
replace_once(old_main, new_main, "default to loopback and enable configurable threaded serving")

# Write once, only after every expected source block was found.
if 'HTTPServer(("0.0.0.0", PORT)' in source:
    raise SystemExit("Unsafe wildcard bind remains; no files changed.")
if 'Access-Control-Allow-Origin","*"' in source:
    raise SystemExit("Wildcard CORS remains; no files changed.")
if 'pip_install(pkg)' in source or 'subprocess.check_call([sys.executable, "-m", "pip"' in source:
    raise SystemExit("Runtime pip installation remains; no files changed.")
path.write_text(source, encoding="utf-8")
print("Hardened server.py:")
for change in changes:
    print(f"- {change}")
print("- constrain static assets to the application bundle")
print("- use a threaded HTTP server")
print("- default bind address to 127.0.0.1")
