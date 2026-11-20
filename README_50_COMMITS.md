# WiFi Analyzer Pro — 100 features / 50 commits

This folder is a feature pack for the existing **NetCore-Technologies/wifi-analyzer-pro** repository. It adds 100 distinct read-only network/RF tools, a searchable feature workbench, local first-run password setup and login/logout, session expiry, fail-closed credential handling, and truthfulness corrections for demo/placeholder telemetry.

## Commit structure

The included `scripts/commit_features.sh` creates **exactly 50 signed commits** on the existing `main` branch. The first commit contains the shared integration plumbing and feature tools F001–F002. Each of the remaining 49 commits adds exactly two independently implemented feature modules. The full ordered message list is in [`COMMITS_50.md`](COMMITS_50.md).

The script uses the Git identity and signing key already configured on your machine. It does not spoof authors, alter timestamps, forge signatures, create a branch, or push automatically. The repository's required-verified-signature ruleset remains intact.

## Apply the folder

1. Make sure your existing checkout is clean and on `main`, then fast-forward it.
2. Extract this ZIP to a temporary directory and copy the contents of its top-level folder into the **root of that existing checkout**:

```bash
cd ~/Documents/wifi-analyzer-pro
git switch main
git pull --ff-only origin main
unzip -o ~/Downloads/wifi-analyzer-pro-50-commit-pack.zip -d /tmp/wifi-analyzer-pro-pack
cp -a /tmp/wifi-analyzer-pro-pack/wifi-analyzer-pro-50-commit-pack/. .
python3 -m py_compile scripts/apply_feature_pack.py scripts/patch_ui_truthfulness.py
bash scripts/commit_features.sh
```

The script expects local `main` to be exactly at the fetched `origin/main` before starting. It refuses to mix any pre-existing ahead commits into the 50-commit series.

The commit script applies its guarded/idempotent integration patches itself, checks for exactly 100 feature modules and manifest entries, runs Python compile/tests, and runs `npm ci`, lint and production build before creating commits. If the frontend checks cannot run, the script stops before committing; do not bypass them for a release.

To review the result:

```bash
git log --oneline --reverse origin/main..HEAD
git rev-list --count origin/main..HEAD
```

The count must be `50`. Every commit must have a verified signature. The working tree must be clean.

When you have reviewed all changes and are ready to update GitHub, run:

```bash
bash scripts/push_main.sh
```

That script re-fetches `origin/main`, rechecks the 50-commit count, verifies that each commit introduces exactly two feature modules, checks signatures, reruns the full tests and frontend build, and only then pushes the existing `main` branch. It does not create a release or tag.

## Local app account

On first launch, the UI offers creation of a local password (12-character minimum). The backend stores a salted scrypt verifier under the user config directory with owner-only file permissions; bearer session tokens are process-local and expire. Five failed logins trigger a temporary lockout. Logout revokes the token. This is a **single local account**, not multi-user RBAC, cloud identity, or enterprise SSO. Keep port `199` on a trusted machine/network; use a VPN or authenticated reverse proxy for remote access.

## Feature catalogue

- `FEATURES_100.md` is the human-readable feature list.
- `wifi_analyzer_backend/feature_plugins/FEATURES.json` is the machine-readable catalogue.
- `wifi_analyzer_backend/feature_plugins/feature_001_*.py` through `feature_100_*.py` are independently callable feature implementations.
- `src/components/FeatureWorkbench.jsx` provides search, JSON input and execution result UI.

The tools work against provided observations and local system/network capabilities. A platform or adapter may return unavailable data; the application must not invent RSSI noise floors, SNR, link rates, throughput, security incidents or channel airtime utilisation. The static preview is labelled as illustrative.

## Verification status of this pack

The feature/auth Python suite was run in the packaging environment: **23 tests passed**, including execution of all 100 feature functions, registry uniqueness, channel planning edge cases, safe exports, password persistence, session expiry, lockout and fail-closed corrupted credential storage. Python compilation also passed. A complete npm install/lint/build was not run in this packaging environment; the commit script performs those checks on your machine and stops before committing when they fail.
