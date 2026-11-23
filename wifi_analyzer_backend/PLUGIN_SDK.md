# Third-party feature plugin SDK

WiFi Analyzer Pro supports separately installed, publisher-signed Python
feature plugins. The plugin system is deliberately disabled by default:
packages are only shown as enabled features after an owner or administrator
explicitly enables them.

## Trust and execution model

A plugin is trusted Python code that executes **inside the WiFi Analyzer Pro
API process**. Ed25519 signatures verify the trusted publisher and the exact
source digest. They do not sandbox Python, isolate memory, restrict system
calls, prevent network access or stop a plugin from accessing resources
available to the API service account.

Only install packages from publishers whose code and release process you
trust. Review the source and requested permissions before adding the
publisher's key to your local trust store. Use a dedicated, non-root
`wifi-analyzer` service account, keep secrets out of that account's
environment unless required, and back up the trust store and plugin registry.
The runtime does not accept plugin uploads through the HTTP API.

The API currently supports one signed `plugin.py` module per package and the
plugin API version `1.0`. Additional Python package dependencies, background
workers, GUI extensions and untrusted-code isolation are not provided by this
SDK.

## Package layout

Install each plugin in its own directory:

```text
plugins/
└── acme.channel_quality/
    ├── manifest.json
    └── plugin.py
```

The directory name must exactly match `plugin_id`. A package contains only
`manifest.json` and `plugin.py` (an optional `README.md` is permitted).
Symlinks, unexpected files, group/world-writable package entries and source
files over 1 MiB are rejected.

## Write the plugin entrypoint

The package exports one `PLUGIN` object created from
`wifi_analyzer_backend.plugin_sdk.FeaturePlugin`:

```python
from wifi_analyzer_backend.plugin_sdk import FeaturePlugin


def run(payload):
    networks = payload.get("networks", [])
    if not isinstance(networks, list):
        raise ValueError("networks must be a list")
    return {
        "network_count": len(networks),
        "status": "measured",
    }


PLUGIN = FeaturePlugin(
    slug="ext_acme_channel_quality",
    name="Acme channel quality",
    description="Count the supplied network observations.",
    parameters={"networks": "network[]"},
    run=run,
)
```

The feature run function accepts one finite JSON object and must return one
finite JSON object. Inputs and outputs are each limited to 1 MiB. Keep
computation bounded and deterministic. Do not create threads, background
services, subprocesses or network listeners from a feature function. Do not
log credentials or raw network inventory.

## Manifest

The signed manifest contains exactly these fields:

| Field | Meaning |
|---|---|
| `schema_version` | Integer `1` |
| `plugin_id` | Lowercase `publisher.plugin` identifier, matching the folder |
| `slug` | Deterministic `ext_<publisher>_<plugin>` feature slug |
| `name` | Display name, 1–120 characters |
| `version` | Semantic version |
| `api_version` | Currently `1.0` |
| `publisher` | The `plugin_id` prefix |
| `key_id` | Ed25519 publisher key identifier |
| `entrypoint` | Fixed value `plugin.py` |
| `source_sha256` | SHA-256 of the exact UTF-8 `plugin.py` bytes |
| `description` | 1–500 character feature description |
| `parameters` | JSON object containing parameter descriptions |
| `permissions` | Unique list of supported required API permissions |
| `signature` | Base64 Ed25519 signature over canonical JSON without this field |

The slug is derived from the publisher and plugin portions of `plugin_id`.
Publisher and plugin names use lowercase letters, digits, underscores and
hyphens. The manifest and source are signed together by including the source
digest in the signed manifest. The host also checks the exact source digest
before importing the code.

## Sign a release

Generate and safeguard a publisher Ed25519 private key outside the plugin
package and outside customer installations. Publish only its 32-byte raw
public key, base64 encoded, to the customer trust store.

Example developer-side signing code:

```python
import json
from pathlib import Path
from wifi_analyzer_backend.plugin_sdk import sign_manifest, source_sha256

source = Path("plugin.py").read_bytes()
manifest = {
    "schema_version": 1,
    "plugin_id": "acme.channel_quality",
    "slug": "ext_acme_channel_quality",
    "name": "Acme channel quality",
    "version": "1.0.0",
    "api_version": "1.0",
    "publisher": "acme",
    "key_id": "acme-release-2026",
    "entrypoint": "plugin.py",
    "source_sha256": source_sha256(source),
    "description": "Count supplied network observations.",
    "parameters": {"networks": "network[]"},
    "permissions": ["diagnostics.read"],
}
signed = sign_manifest(manifest, private_key)
Path("manifest.json").write_text(
    json.dumps(signed, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    encoding="utf-8",
)
```

`private_key` is an Ed25519 private-key object from the cryptography package.
The private key must never be placed in the plugin directory, the customer
trust store, the application repository or an ordinary customer environment
file. The publisher should sign and publish immutable release archives and
checksums.

## Configure a publisher trust store

The trust store is a JSON object mapping key IDs to base64-encoded raw
Ed25519 public keys:

```json
{
  "acme-release-2026": "BASE64_ENCODED_32_BYTE_ED25519_PUBLIC_KEY"
}
```

On Linux, keep it in a root-controlled configuration directory and make it
readable by the service account but not writable by group/other users:

```sh
sudo install -d -o root -g root -m 0755 /etc/wifi-analyzer-pro
sudo install -o root -g wifi-analyzer -m 0640 plugin-trust-keys.json /etc/wifi-analyzer-pro/plugin-trust-keys.json
```

The trust store accepts up to 100 keys. Each key is identified by a unique
key ID. Key rotation should add the new public key before signing a release
with its key ID, then remove the old key after all packages signed by it have
been retired.

## Install and manage a package

Install the release directory into the configured plugin directory using the
application service account. For the systemd installation, the default path is
`/var/lib/wifi-analyzer-pro/plugins`:

```sh
sudo install -d -o wifi-analyzer -g wifi-analyzer -m 0700 \
  /var/lib/wifi-analyzer-pro/plugins/acme.channel_quality
sudo install -o wifi-analyzer -g wifi-analyzer -m 0600 manifest.json \
  /var/lib/wifi-analyzer-pro/plugins/acme.channel_quality/manifest.json
sudo install -o wifi-analyzer -g wifi-analyzer -m 0600 plugin.py \
  /var/lib/wifi-analyzer-pro/plugins/acme.channel_quality/plugin.py
```

The API exposes an admin-only plugin directory and lifecycle:

| Operation | Endpoint | Result |
|---|---|---|
| List installed packages | `GET /api/plugins` | Signature status and enabled state |
| Enable | `POST /api/plugins/{plugin_id}/enable` | Verify package, import entrypoint and persist enabled state |
| Reload | `POST /api/plugins/{plugin_id}/reload` | Reverify and reimport an enabled package |
| Disable | `POST /api/plugins/{plugin_id}/disable` | Remove from runtime registry and persist disabled state |

Lifecycle operations require the `plugins.manage` permission (owner/admin),
are rate limited and are audit-first. A plugin must pass signature, API
version, manifest, source-digest and entrypoint checks before enable succeeds.
The plugin API does not provide package upload or remote install.

Enabled plugins are appended to `GET /api/features` and can be run through the
normal `POST /api/features/{slug}` endpoint. The caller must have
`diagnostics.run` plus every permission listed by the plugin manifest.
Normal site-scope validation and monthly feature-run metering remain active.
Disabling a plugin removes its slug from the live catalogue and unloads its
module from the runtime registry.

## Limits and operational considerations

- At most 100 plugin packages are discovered.
- Manifest files are limited to 16 KiB and source files to 1 MiB.
- Plugin directory, manifest and source may not be symlinks or writable by
  group/other users.
- Plugin state is stored in a local SQLite registry separate from built-in
  modules. The built-in manifest and 208 built-in feature IDs are unchanged.
- A reload replaces the module object for future invocations. It cannot safely
  terminate work a plugin may already have started; this is another reason
  plugins must not start threads, subprocesses or background services.
- A plugin can block its API request or use any OS/Python capability available
  to the service process. There is no execution timeout or security sandbox in
  this version. Use only reviewed, signed code from trusted publishers.
