# Vendor licensing control plane

This deployment is for NetCore infrastructure only. Do not run it in customer installations. Customer deployments use `compose.yaml` and receive only the public Ed25519 verification key and the HTTPS URL of this service.

## Generate the signing keypair

Run once on a trusted vendor machine:

```bash
python3 -m pip install -r wifi_analyzer_backend/requirements.txt
sudo python3 scripts/generate_vendor_license_key.py --key-id primary --output vendor-secrets/vendor-license-signing-key.b64 --uid 10001 --gid 10001
```

The key generator refuses to overwrite an existing file, writes the private seed as base64 with mode `0600`, and prints only the public verification key. The UID/GID flags make the private file readable by the non-root service account in Docker. Store the private file in an encrypted, access-controlled offline backup. Never commit it or distribute it to customers.

## Configure vendor Stripe

Create recurring Stripe Prices for Pro, Business and Enterprise in the vendor's Stripe account. Set the Pro monthly recurring Price to **30 per month in the currency you choose**; set higher Business and Enterprise prices to match their support and usage limits. The application uses Stripe Price IDs and does not hard-code a currency.

Copy `.env.vendor.example` to `.env.vendor`, then set:
- `WIFI_ANALYZER_LICENSE_SERVICE_PUBLIC_URL` to your public HTTPS origin.
- `WIFI_ANALYZER_VENDOR_LICENSE_SIGNING_PRIVATE_KEY_FILE` to the generated key file.
- The vendor Stripe secret and webhook signing secret.
- The Pro recurring Price ID; optionally configure Business and Enterprise Price IDs.

Configure a Stripe webhook at `https://licenses.your-domain.example/api/webhook` for `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated` and `customer.subscription.deleted`. Copy the endpoint signing secret to `WIFI_ANALYZER_VENDOR_STRIPE_WEBHOOK_SECRET`.

## Deploy

```bash
cp .env.vendor.example .env.vendor
docker compose --env-file .env.vendor -f compose.vendor-licensing.yaml up -d --build
```

The service runs as UID 10001 with a read-only root filesystem, dedicated persistent SQLite volume and read-only mount of the private key. The key file must be owned by UID/GID 10001 and have no group/other permissions. The service binds to loopback by default. Put a trusted TLS reverse proxy in front of port 1999; never expose its plain HTTP listener directly. Add proxy-level request-size, connection and rate limits.

Verify `/health` and `/api/public-key` through the HTTPS domain. The public-key endpoint reveals only the verification key and key ID.

## Configure customers

On each customer installation set `WIFI_ANALYZER_VENDOR_LICENSE_SERVICE_URL`, `WIFI_ANALYZER_VENDOR_LICENSE_PUBLIC_KEY` (the public key from key generation) and `WIFI_ANALYZER_VENDOR_LICENSE_KEY_ID`. Restart the customer API. Workspace owners can open **Plans & Licensing**, purchase through NetCore's Stripe Checkout and select **Sync purchased licence** after payment. The customer installation stores an installation-bound activation credential privately and receives short-lived signed renewals. Vendor Stripe secrets and the signing private key never leave this service.

## Operations

- Back up the SQLite volume and the signing private key separately.
- Do not rotate or replace the private key without publishing the new public key to customer installations first.
- A payment unlocks the product only after Stripe's signed webhook confirms it. Monitor Stripe webhook delivery failures.
- Signed licences are valid for up to 24 hours, with six hours of offline grace. Customer installations must sync while their subscription is active.
- Configure Stripe Customer Portal settings before enabling subscription-management links.
- This is a vendor-issued licence control plane, not yet a pooled multi-tenant network operations SaaS; customer site/network data remains local to each installation.
