# Contributing

Thank you for helping improve WiFi Analyzer Pro.

## Before opening an issue

Include the operating system and version, Python and Node versions, Wi-Fi adapter/driver, the exact action that failed, expected versus actual results, and relevant redacted logs. Do not publish private SSIDs, BSSIDs, client MAC addresses, public IP addresses, router credentials or API tokens.

## Development setup

```bash
npm install
python3 -m venv wifi_analyzer_backend/.venv
wifi_analyzer_backend/.venv/bin/python -m pip install -r wifi_analyzer_backend/requirements.txt
npm run dev
```

Run the local checks before submitting:

```bash
npm run lint
npm run build
python3 -m compileall -q wifi_analyzer_backend tests
python3 -m unittest discover -s tests -v
```

## Pull requests

Keep pull requests focused. Include tests for new parsing, platform behaviour and error paths. Do not report synthetic demo data as a real observation. Keep the existing dashboard design language and check desktop and narrow viewport layouts when changing UI components.

## Security issues

Do not publish exploitable vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md) for responsible disclosure.
