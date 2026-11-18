# WiFi Analyzer Pro release, quality and product-site foundation

This bundle is prepared against `NetCore-Technologies/wifi-analyzer-pro` `main` at commit `fe46cc98f1b6f2f63f8671bc7e26130e8456c858`. It has **not** been committed or released on GitHub.

## Why ChatGPT cannot push directly

The organisation GitHub App installation initially excluded this repository; that selection has since been changed to `All repositories`, and the repository is now visible to the installation. Writes now reach GitHub but are rejected with HTTP `409`: the repository ruleset `https://github.com/NetCore-Technologies/wifi-analyzer-pro/rulesets/18899351` actively enforces `required_signatures` on all branches and has no bypass actors. The GitHub connector's Contents API creates unsigned commits, so GitHub correctly rejects them. This is a signing-policy block, not a missing repository selection or a bad commit.

**Keep the verified-signature rule enabled.** Apply and commit from your local clone using a signing key that is registered with your GitHub account.

For an existing SSH signing key (the public key must be added in GitHub Settings → SSH and GPG keys as a *Signing key*):

```bash
git config --local gpg.format ssh
git config --local user.signingkey ~/.ssh/id_ed25519
git config --local commit.gpgsign true
```

For an already-configured GPG signing key, simply enable signed commits in the repository:

```bash
git config --local commit.gpgsign true
```

Check the configured signer before applying: `git config --show-origin --get user.signingkey` and `git config --get gpg.format`. Do not share a private signing key.

## Apply and validate

From the root of a clean local clone:

```bash
git status --short
unzip -o wifi-analyzer-pro-foundation.zip -d .
python3 patches/harden_server.py
python3 patches/fix_ai_panel_duplicate_tips.py
npm install --no-audit --no-fund  # generates/updates package-lock.json once
npm ci --no-audit --no-fund        # confirms the committed lockfile is installable
npm run lint
npm run build
python3 -m compileall -q wifi_analyzer_backend tests
python3 -m unittest discover -s tests -v
```

The two Python patch scripts are guarded: they stop without writing if the expected upstream code blocks do not match. Review their diffs before committing. They remove runtime package installation, stop fabricated live scans/metrics, improve 6 GHz/security parsing, default the unauthenticated service to loopback, harden static path resolution/CORS and use a threaded server. The UI patch fixes the duplicate `tips` declaration (a production-build blocker), removes canned AI security claims, fixes the stale polling closure, connects Scan to the backend and uses the current host for local API requests.

## Commit to the existing `main` branch

Do not create a side branch. Once the local checks pass and the signing key is configured, create logical, verified commits on `main`:

```bash
git add .github/workflows/ci.yml .github/workflows/dependency-review.yml .github/dependabot.yml .eslintrc.cjs tests/
git commit -S -m "ci: add frontend and backend quality gates"
git add .github/workflows/release.yml Dockerfile .dockerignore package.json package-lock.json
git commit -S -m "build(release): package cross-platform binaries and containers"
git add .github/workflows/pages.yml site/ README.md CHANGELOG.md CONTRIBUTING.md
git commit -S -m "feat(site): publish WiFi Analyzer Pro product website"
git add wifi_analyzer_backend/ install_windows.bat patches/
git commit -S -m "fix(runtime): harden local Wi-Fi diagnostics and installers"
git push origin main
```

GitHub must show each new commit as **Verified**. If it does not, stop and fix the signing-key configuration rather than weakening the ruleset.

## Release assets

After these changes are on `main`, publish a tag matching `package.json` (`1.0.7`):

```bash
git tag -s v1.0.7 -m "WiFi Analyzer Pro v1.0.7"
git push origin v1.0.7
```

The release matrix builds Linux x64 and ARM64, macOS ARM64 and Intel x64, and Windows x64. Expected assets include macOS DMG/tar.gz; Linux AppImage/DEB/ELF/installer/tar.gz; Windows EXE/MSI/batch/PowerShell; platform SHA-256 manifests; and a combined `SHA256SUMS`. The workflow also publishes a multi-architecture GHCR image with SBOM, provenance and a keyless Cosign signature.

The macOS outputs are not notarised unless all five Apple Developer ID / notarisation secrets documented in `README.md` are configured.

## GitHub Pages

Enable GitHub Pages once in repository Settings → Pages with **GitHub Actions** as the deployment source. The workflow publishes `site/` at:

`https://netcore-technologies.github.io/wifi-analyzer-pro/`

The site reads the latest public GitHub Release API and creates direct links to available platform assets.

## Enterprise deployment warning

This is a release and reliability foundation, **not** an enterprise security certification. The current server has no built-in authentication, SSO or RBAC. It defaults to loopback; remote deployments must use a VPN or authenticated reverse proxy and firewall restrictions. Do not expose port `199` directly to the public internet.
