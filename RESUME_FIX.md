# WiFi Analyzer Pro — resume and repair pack

This fix pack is based on the live `main` branch at commit `4815f54f47480df560abaf48e747fac4a6bb8613` (18 November 2026). It adds one guarded repair script. It does not overwrite backend or UI files and does not create a branch.

## What the current GitHub CI actually reported

- **Frontend production build:** `actions/setup-node` stopped because `package-lock.json` is missing while `cache: npm` is enabled. `npm ci` never ran.
- **Python tests:** all four Python 3.10–3.13 jobs ran 13 tests and failed the same backend regressions. The new `tests/test_server_basics.py` expects the existing `patches/harden_server.py` changes to have been applied to `wifi_analyzer_backend/server.py`.
- **Pages:** the custom `Publish product website` workflow failed at `upload-pages-artifact` because the repository has no `site/index.html`.
- **Root entry point:** commit `4815f54` replaced the Vite React shell in `/index.html` with the marketing page. This prevents the root Vite build from loading `src/main.jsx`.

The repair script fixes the site/app separation and adds a CI preflight so a missing lockfile or misplaced page is reported explicitly. It keeps the current marketing page intact by moving it to `site/index.html`.

## Apply on the existing `main` branch

From your local clone:

```bash
git switch main
git pull --ff-only origin main
unzip -o ~/Downloads/wifi-analyzer-pro-resume-fix.zip -d .
python3 patches/restore_vite_and_pages.py
python3 patches/harden_server.py
python3 patches/fix_ai_panel_duplicate_tips.py
```

The last two scripts are already in the repository. They remove fabricated live Wi-Fi data, implement 6 GHz parsing and WPA3 detection, restore explicit demo-mode handling, harden the local HTTP service, remove the duplicate AI `tips` declaration, replace canned AI findings, and connect Scan/polling to the backend.

Generate the npm lockfile once, then verify a clean reproducible install:

```bash
npm install --no-audit --no-fund
npm ci --no-audit --no-fund
npm run lint
npm run build
python3 -m compileall -q wifi_analyzer_backend tests
python3 -m unittest discover -s tests -v
git diff --check
```

Do not skip `npm install`: the current repository has no `package-lock.json`, and CI, Docker and release builds are configured around `npm ci`. Commit the generated lockfile.

## Review and commit

```bash
git status --short
git diff --stat
git diff -- index.html site/index.html .github/workflows/ci.yml wifi_analyzer_backend/server.py src/App.jsx src/hooks/useWifiData.js
```

After every local check passes, make a signed commit on the existing `main` branch and push it:

```bash
git add index.html site/index.html .github/workflows/ci.yml \
  wifi_analyzer_backend/server.py src/App.jsx src/hooks/useWifiData.js \
  package-lock.json patches/restore_vite_and_pages.py RESUME_FIX.md
git commit -S -m "fix: restore app entry point and apply live diagnostics"
git push origin main
```

The repository requires verified signatures. Keep that rule enabled; the earlier GitHub App file-write attempt was rejected because it cannot sign commits using your local key. Confirm GitHub labels the pushed commit **Verified**.

## Release sequence

Do not tag `v1.0.7` until the Quality gates workflow on the repaired `main` commit is green. Then run:

```bash
git tag -s v1.0.7 -m "WiFi Analyzer Pro v1.0.7"
git push origin v1.0.7
```

The existing release workflow is configured for Linux x64/ARM64, macOS Apple Silicon/Intel, and Windows x64. It has not generated these binaries yet. macOS downloads will not be notarised unless the five Apple Developer ID/notarisation secrets are configured.

## Current verified state

- Latest observed `main` commit: `4815f54f47480df560abaf48e747fac4a6bb8613` (verified PGP signature).
- Latest published release: `v1.0.6`, dated 16 July 2026.
- Latest `Quality gates` workflow run: failed at frontend setup and Python tests.
- Latest custom product-site workflow run: failed because its `site/` upload input was absent.
- No `v1.0.7` tag/release or new platform binary has been published yet.
