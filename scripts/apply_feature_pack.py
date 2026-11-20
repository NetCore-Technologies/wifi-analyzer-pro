#!/usr/bin/env python3
"""Integrate the WiFi Analyzer Pro feature workbench and local auth gate."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path.cwd()


def read(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        raise SystemExit(f"Missing expected repository file: {path}")
    return target.read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    (ROOT / path).write_text(content, encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    # Most replacements retain the original anchor inside the replacement.
    # Check the full replacement first so applying the pack twice is safe.
    if new in text:
        return text
    count = text.count(old)
    if count == 0:
        raise SystemExit(f"Could not find integration anchor for {label}; no source files were changed")
    if count != 1:
        raise SystemExit(f"Expected one integration anchor for {label}, found {count}; no source files were changed")
    return text.replace(old, new, 1)


def main() -> int:
    if not (ROOT / ".git").is_dir():
        raise SystemExit("Run this script from the root of your existing Git checkout")
    import subprocess
    branch = subprocess.check_output(["git", "branch", "--show-current"], text=True).strip()
    if branch != "main":
        raise SystemExit(f"Expected the existing main branch, found {branch!r}; switch to main first")

    server = read("wifi_analyzer_backend/server.py")
    app = read("src/App.jsx")
    main_jsx = read("src/main.jsx")
    hook = read("src/hooks/useWifiData.js")
    vite = read("vite.config.js")
    docker = read("Dockerfile")
    release = read(".github/workflows/release.yml")
    arm_build = read("wifi_analyzer_backend/build_arm64_binary.sh")
    readme = read("README.md")
    package = json.loads(read("package.json"))

    # Validate all source anchors before writing anything.
    required = [
        ("from urllib.parse import urlparse, unquote", "server URL parsing import"),
        ("    def do_GET(self):\n        path = urlparse(self.path).path\n", "server GET handler"),
        ("    def do_OPTIONS(self):", "server OPTIONS handler"),
        ("            \"/api/system\": get_system,", "server API route table"),
        ("            <Settings size={14}/>", "application header settings control"),
        ("  const allItems=NAV.flatMap(g=>g.items);", "application panel registration"),
        ("{id:\"api\",     label:\"API\",            Icon:Code},", "application navigation"),
    ]
    for anchor, label in required:
        if anchor not in (server + app):
            raise SystemExit(f"Missing integration anchor: {label}; no source files were changed")

    # Backend imports and auth manager.
    server = replace_once(
        server,
        "from urllib.parse import urlparse, unquote\n",
        "from urllib.parse import urlparse, unquote\n\ntry:\n    from wifi_analyzer_backend.auth import AuthManager\n    from wifi_analyzer_backend.feature_plugins import catalog as feature_catalog, run as run_feature, count as feature_count\nexcept ImportError:\n    from auth import AuthManager\n    from feature_plugins import catalog as feature_catalog, run as run_feature, count as feature_count\n",
        "backend feature/auth imports",
    )
    server = replace_once(server, "# ── Helpers ───────────────────────────────────────────────────────────────────\n", "AUTH = AuthManager()\n\n# ── Helpers ───────────────────────────────────────────────────────────────────\n", "auth manager initialization")
    server = replace_once(
        server,
        'DEFAULT_CORS_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}',
        'DEFAULT_CORS_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:199", "http://127.0.0.1:199"}',
        "default same-origin dashboard origins",
    )

    # CORS must allow the bearer header and JSON POSTs from the Vite dev origin.
    server = replace_once(server, 'self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")', 'self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")', "CORS allowed methods")
    server = replace_once(server, 'self.send_header("Access-Control-Allow-Headers", "Content-Type")', 'self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")', "CORS allowed headers")

    # Protected GET API and public auth status endpoint.
    get_old = "    def do_GET(self):\n        path = urlparse(self.path).path\n"
    get_new = '''    def _bearer_token(self):
        value = self.headers.get("Authorization", "")
        scheme, _, token = value.partition(" ")
        return token.strip() if scheme.lower() == "bearer" else None

    def do_GET(self):
        path = urlparse(self.path).path
        token = self._bearer_token()
        if path == "/api/auth/status":
            self.send_json(AUTH.status(token))
            return
        if path.startswith("/api/") and not AUTH.validate(token):
            self.send_json({"error": "Authentication required"}, 401)
            return
'''
    server = replace_once(server, get_old, get_new, "GET authentication gate")
    server = replace_once(
        server,
        '            "/api/system": get_system,\n',
        '            "/api/features": lambda: {"features": feature_catalog(), "count": feature_count()},\n            "/api/system": get_system,\n',
        "feature catalog API route",
    )
    server = replace_once(
        server,
        '"security": {"authentication": False, "remote_access": "Use a VPN or authenticated reverse proxy"},',
        '"security": {"authentication": AUTH.configured(), "authentication_method": "local password + expiring bearer session", "remote_access": "Use a VPN or authenticated reverse proxy"},\n                "feature_count": feature_count(),',
        "capabilities authentication reporting",
    )

    # Add safe JSON POST routes: login/setup/logout and feature execution only.
    post_block = '''
    def do_POST(self):
        path = urlparse(self.path).path
        origin = self.headers.get("Origin")
        fetch_site = self.headers.get("Sec-Fetch-Site", "")
        if (origin and origin not in CORS_ORIGINS) or (not origin and fetch_site == "cross-site"):
            self.send_json({"error": "Origin is not allowed"}, 403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json({"error": "Invalid Content-Length"}, 400)
            return
        if length < 0 or length > 65536:
            self.send_json({"error": "Request body exceeds the 64 KiB limit"}, 413)
            return
        try:
            raw = self.rfile.read(length) if length else b"{}"
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Request body must be a JSON object")

            if path == "/api/auth/setup":
                token = AUTH.setup(str(payload.get("password", "")))
                self.send_json({"ok": True, "token": token, "status": AUTH.status(token)}, 201)
                return
            if path == "/api/auth/login":
                token = AUTH.login(str(payload.get("password", "")))
                self.send_json({"ok": True, "token": token, "status": AUTH.status(token)})
                return
            if path == "/api/auth/logout":
                revoked = AUTH.logout(self._bearer_token())
                self.send_json({"ok": True, "revoked": revoked})
                return
            prefix = "/api/features/"
            if path.startswith(prefix):
                token = self._bearer_token()
                if not AUTH.validate(token):
                    self.send_json({"error": "Authentication required"}, 401)
                    return
                slug = path[len(prefix):]
                if not re.fullmatch(r"[a-z0-9_]{1,80}", slug):
                    self.send_json({"error": "Invalid feature name"}, 400)
                    return
                self.send_json(run_feature(slug, payload))
                return
            self.send_json({"error": "Not found"}, 404)
        except PermissionError as error:
            self.send_json({"error": str(error)}, 401)
        except KeyError as error:
            self.send_json({"error": str(error)}, 404)
        except ValueError as error:
            self.send_json({"error": str(error)}, 400)
        except RuntimeError as error:
            self.send_json({"error": str(error)}, 409)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as error:
            print(f"[ERROR] POST {path}: {error}")
            if not self.wfile.closed:
                self.send_json({"error": "Internal server error"}, 500)

'''
    if "    def do_POST(self):" not in server:
        server = replace_once(server, "if __name__ == \"__main__\":\n", post_block + "if __name__ == \"__main__\":\n", "POST handler insertion")

    # UI imports, bearer-aware API helper, workbench navigation and logout button.
    app = replace_once(app, "  Moon, Sun, Menu, X, Terminal, Package, Antenna\n", "  Moon, Sun, Menu, X, Terminal, Package, Antenna, LogOut\n", "LogOut icon import")
    app = replace_once(app, "} from \"lucide-react\";\n", "} from \"lucide-react\";\nimport FeatureWorkbench from \"./components/FeatureWorkbench.jsx\";\nimport { useAuth } from \"./auth/AuthContext.jsx\";\nimport { apiFetch } from \"./lib/api.js\";\n", "workbench/auth imports")
    app = app.replace("fetch(`${API_BASE}/api/", "apiFetch(`${API_BASE}/api/")
    if "apiFetch(`${API_BASE}/api/" not in app:
        raise SystemExit("Could not wire API helper into App.jsx")
    ui_adapter = '''  const toUiNetwork = (network) => ({
    ...network,
    ssid: typeof network.ssid === "string" ? network.ssid : "",
    bssid: network.bssid || "",
    ch: network.ch ?? network.channel ?? 0,
    sec: network.sec ?? network.security ?? network.security_detail ?? "Unknown",
    snr: network.snr ?? null,
    width: network.width ?? network.channel_width ?? "—",
    wifi: network.wifi ?? "Unknown",
    clients: network.clients ?? "—",
    vendor: network.vendor ?? "Unknown",
    rogue: network.rogue === true,
  });
  const toUiDevice = (device) => ({
    ...device,
    name: device.name ?? device.hostname ?? device.ip ?? "Unknown device",
    ip: device.ip ?? "—",
    mac: device.mac ?? "—",
    vendor: device.vendor ?? "Unknown",
    type: device.type ?? "Unknown",
    online: device.online ?? null,
    bw: device.bw ?? null,
    rssi: device.rssi ?? null,
    gw: device.gw === true,
  });
  const networks=Array.isArray(liveNets) ? liveNets.map(toUiNetwork) : NETWORKS;
  const devices=Array.isArray(liveDevs) ? liveDevs.map(toUiDevice) : DEVICES;
'''
    app = replace_once(
        app,
        "  const networks=liveNets||NETWORKS;\n  const devices=liveDevs||DEVICES;\n",
        ui_adapter,
        "live API data normalisation",
    )
    app = replace_once(
        app,
        "        <Stat label=\"Devices Found\"   value={DEVS.length} sub={`${DEVS.filter(d=>d.online!==false).length} online · ${DEVS.filter(d=>d.online===false).length} offline`} col={C.cyan} Icon={Smartphone} delay={1}/>",
        "        <Stat label=\"Devices Found\"   value={DEVS.length} sub={`${DEVS.filter(d=>d.online===true).length} online · ${DEVS.filter(d=>d.online===false).length} offline · ${DEVS.filter(d=>d.online==null).length} unknown`} col={C.cyan} Icon={Smartphone} delay={1}/>",
        "device count does not assume unknown is online",
    )
    app = replace_once(
        app,
        "                  <PulseDot col={d.online?C.green:C.red}/>\n                  <span style={{fontSize:10,color:d.online?C.green:C.red,fontWeight:600}}>{d.online?\"Online\":\"Offline\"}</span>",
        "                  <PulseDot col={d.online==null?C.yellow:d.online?C.green:C.red}/>\n                  <span style={{fontSize:10,color:d.online==null?C.yellow:d.online?C.green:C.red,fontWeight:600}}>{d.online==null?\"Status unknown\":d.online?\"Online\":\"Offline\"}</span>",
        "device status unknown state",
    )
    app = replace_once(
        app,
        "{[[\"IP\",d.ip,true],[\"MAC\",d.mac,true],[\"Bandwidth\",d.bw+\" Mbps\",false]].map(([k,v,mono])=>(",
        "{[[\"IP\",d.ip,true],[\"MAC\",d.mac,true],[\"Bandwidth\",d.bw==null?\"—\":d.bw+\" Mbps\",false]].map(([k,v,mono])=>(",
        "unknown bandwidth display",
    )
    app = replace_once(
        app,
        "                  <AnimatedBars rssi={d.rssi}/>",
        "                  {d.rssi==null?<span style={{fontSize:11,color:C.muted}}>—</span>:<AnimatedBars rssi={d.rssi}/>} ",
        "unknown device RSSI display",
    )
    app = replace_once(
        app,
        "        <Stat label=\"Devices Online\" value={`${devs.filter(d=>d.online!==false).length} / ${devs.length}`} sub={devs.filter(d=>!d.vendor||d.vendor===\"???\").length>0?\"Unknown device flagged\":\"All identified\"} col={C.yellow} Icon={Smartphone} delay={4}/>",
        "        <Stat label=\"Devices Observed\" value={devs.length} sub=\"Current neighbour-table entries\" col={C.yellow} Icon={Smartphone} delay={4}/>",
        "dashboard device count wording",
    )
    app = replace_once(app, "export default function App() {\n", "export default function App() {\n  const { logout } = useAuth();\n", "logout hook")
    app = replace_once(app, '{id:"api",     label:"API",            Icon:Code},', '{id:"api",     label:"API",            Icon:Code},\n    {id:"workbench",label:"Feature Workbench",Icon:Wrench},', "workbench navigation item")
    app = replace_once(app, "  const allItems=NAV.flatMap(g=>g.items);\n", "  panels.workbench = <FeatureWorkbench />;\n\n  const allItems=NAV.flatMap(g=>g.items);\n", "workbench panel registration")
    settings_block = '''            <button onClick={()=>addToast("Settings coming in v1.1.0","info")}
              style={{width:32,height:32,display:"flex",alignItems:"center",justifyContent:"center",
                background:C.card2,border:`1px solid ${C.border}`,borderRadius:7,
                cursor:"pointer",color:C.muted,transition:"all 0.15s"}}>
              <Settings size={14}/>
            </button>'''
    logout_block = settings_block + '''
            <button onClick={logout} title="Sign out" aria-label="Sign out"
              style={{width:32,height:32,display:"flex",alignItems:"center",justifyContent:"center",
                background:C.card2,border:`1px solid ${C.border}`,borderRadius:7,
                cursor:"pointer",color:C.muted,transition:"all 0.15s"}}>
              <LogOut size={14}/>
            </button>'''
    app = replace_once(app, settings_block, logout_block, "header logout control")

    # All backend API fetches must carry the session bearer token.
    hook = hook.replace("fetch(`${API_BASE}/api/", "apiFetch(`${API_BASE}/api/")
    if "apiFetch(`${API_BASE}/api/" not in hook:
        raise SystemExit("Could not wire API helper into useWifiData.js")
    hook = replace_once(hook, "import { useState, useEffect, useCallback, useRef } from 'react';\n", "import { useState, useEffect, useCallback, useRef } from 'react';\nimport { apiFetch } from '../lib/api.js';\n", "hook API helper import")

    expected_main = '''import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
'''
    new_main = '''import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import AuthGate from './auth/AuthGate.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <AuthGate>
      <App />
    </AuthGate>
  </React.StrictMode>
)
'''
    if main_jsx == expected_main:
        main_jsx = new_main
    elif "<AuthGate>" not in main_jsx:
        raise SystemExit("src/main.jsx differs from the expected bootstrap; no source files were changed")

    # This project uses ESM (package.json type=module); __dirname is not
    # provided by Node in an ES module. Derive it from import.meta.url.
    if "path.resolve(__dirname, './src')" in vite and "fileURLToPath(import.meta.url)" not in vite:
        vite = vite.replace(
            "import path from 'path'\n",
            "import path from 'node:path'\nimport { fileURLToPath } from 'node:url'\n\nconst __dirname = path.dirname(fileURLToPath(import.meta.url))\n",
            1,
        )
    if "path.resolve(__dirname, './src')" in vite and "fileURLToPath(import.meta.url)" not in vite:
        raise SystemExit("Could not make vite.config.js ESM-safe; no source files were changed")

    # Restore dependencies to the known lockfile-compatible major versions.
    dev = package.get("devDependencies", {})
    desired = {"@types/react": "^18.3.3", "@types/react-dom": "^18.3.0", "eslint": "^8.57.0", "tailwindcss": "^3.4.6"}
    for name, version in desired.items():
        if name not in dev:
            raise SystemExit(f"package.json is missing expected devDependency {name}")
        dev[name] = version


    # Frozen binaries and containers must include the separate auth and feature
    # modules. PyInstaller does not infer importlib-discovered modules reliably.
    docker = replace_once(
        docker,
        "COPY wifi_analyzer_backend/server.py ./server.py\n",
        "COPY wifi_analyzer_backend/server.py ./server.py\nCOPY wifi_analyzer_backend/auth.py ./auth.py\nCOPY wifi_analyzer_backend/feature_plugins ./feature_plugins\n",
        "Docker runtime feature/auth modules",
    )
    release_anchor = "\n".join([
        '            --specpath build \\',
        '            --add-data "dist${SEP}dist" \\',
        '',
    ])
    release_replacement = "\n".join([
        '            --specpath build \\',
        '            --collect-submodules feature_plugins \\',
        '            --hidden-import auth \\',
        '            --add-data "dist${SEP}dist" \\',
        '',
    ])
    release = replace_once(release, release_anchor, release_replacement, "release PyInstaller hidden modules")

    arm_anchor = "\n".join([
        '  --specpath build \\',
        '  --add-data "dist:dist" \\',
        '',
    ])
    arm_replacement = "\n".join([
        '  --specpath build \\',
        '  --collect-submodules feature_plugins \\',
        '  --hidden-import auth \\',
        '  --add-data "dist:dist" \\',
        '',
    ])
    arm_build = replace_once(arm_build, arm_anchor, arm_replacement, "ARM64 PyInstaller hidden modules")
    arm_build = replace_once(arm_build, "npm install --no-audit --no-fund", "npm ci --no-audit --no-fund", "ARM64 deterministic frontend install")

    readme = replace_once(
        readme,
        "| `GET /api/has_wifi` | Wi-Fi adapter availability |\n",
        "| `GET /api/auth/status` | Local account setup/session status |\n| `POST /api/auth/setup` | Configure the first-run local password |\n| `POST /api/auth/login` | Create an expiring local bearer session |\n| `POST /api/auth/logout` | Revoke the current bearer session |\n| `GET /api/features` | Authenticated catalogue of the 100 feature tools |\n| `POST /api/features/{slug}` | Execute one read-only feature tool |\n| `GET /api/has_wifi` | Wi-Fi adapter availability |\n",
        "README authentication and feature API table",
    )
    readme = replace_once(
        readme,
        "**Important:** the current HTTP API does not provide user authentication or enterprise SSO/RBAC. Keep it on a trusted machine/network. Do not expose port `199` directly to the public internet. For team or remote access, place it behind a VPN or an authenticated reverse proxy and restrict network access. Review [SECURITY.md](SECURITY.md) before deployment.",
        "**Authentication:** the local API requires a first-run password and expiring bearer session for protected endpoints. The password verifier is stored in the user config directory with owner-only file permissions; session tokens are process-local and are not persisted. Write requests also enforce the configured Origin allowlist. For a dashboard served from a non-loopback LAN hostname, set `WIFI_ANALYZER_CORS_ORIGINS` to the exact dashboard origin (for example, `http://192.168.1.20:199`). This is a single local account, not enterprise SSO, multi-user RBAC or an identity provider. Keep it on a trusted machine/network. Do not expose port `199` directly to the public internet. For remote access, use a VPN or authenticated reverse proxy and restrict network access. Review [SECURITY.md](SECURITY.md) before deployment.",
        "README authentication and deployment guidance",
    )
    # All source updates are ready; write only after the validation phase above.
    write("wifi_analyzer_backend/server.py", server)
    write("Dockerfile", docker)
    write(".github/workflows/release.yml", release)
    write("wifi_analyzer_backend/build_arm64_binary.sh", arm_build)
    write("README.md", readme)
    write("src/App.jsx", app)
    write("src/main.jsx", main_jsx)
    write("src/hooks/useWifiData.js", hook)
    write("vite.config.js", vite)
    write("package.json", json.dumps(package, indent=2) + "\n")
    print("Applied the 100-feature registry/API, local login/logout, workbench UI, lockfile-compatible dependency pins and ESM-safe Vite path resolution.")
    print("Feature modules are committed in 50 signed changesets, with two independently callable tools in each commit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
