# API rate limiting

The local API applies bounded token-bucket policies to expensive and
authentication-sensitive operations.

| Endpoint class | Burst capacity | Refill period | Identity |
|---|---:|---:|---|
| First-run setup | 3 | 5 minutes | Direct TCP peer IP |
| Login | 8 | 1 minute | Direct TCP peer IP |
| Wireless scan | 15 | 1 minute | Authenticated account |
| Speed test | 2 | 5 minutes | Authenticated account |
| Feature execution | 30 | 1 minute | Authenticated account |
| Site audit | 5 | 1 minute | Authenticated account |
| Live capture start | 4 | 15 minutes | Authenticated account |
| Scheduled report enqueue | 20 | 1 minute | Authenticated account |

A throttled request receives HTTP 429, a JSON `retry_after_seconds` field,
the standard `Retry-After` header and rate-limit metadata headers.

Authenticated operations are keyed by stable local account ID rather than
bearer token, so creating a new session does not reset the account budget.
Setup/login use the direct TCP peer address; the server deliberately ignores
client-supplied `X-Forwarded-For`. Behind a reverse proxy, configure
per-client rate limits at the trusted proxy because the API sees the proxy IP.

The token-bucket store is protected by a thread lock, hashes its composite keys,
expires idle entries after one hour and caps memory at 8,192 buckets. It is
in-memory and resets on process restart. It is not a distributed quota service
or commercial usage meter; multi-process deployments need an aggregate gateway
limit.
