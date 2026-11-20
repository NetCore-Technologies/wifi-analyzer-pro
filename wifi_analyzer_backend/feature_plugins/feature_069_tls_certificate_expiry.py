"""TLS certificate expiry: Read the expiry date of a TLS certificate with a short connection timeout."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    import ssl,socket,datetime
    host=str(p.get("host","")); port=int(number(p.get("port"),443))
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}",host) or not 1<=port<=65535: raise ValueError("Valid host and port are required")
    context=ssl.create_default_context()
    try:
        with socket.create_connection((host,port),timeout=3) as sock:
            with context.wrap_socket(sock,server_hostname=host) as tls: cert=tls.getpeercert()
    except OSError as exc:
        return {"host":host,"error":str(exc),"checked":False}
    expiry=datetime.datetime.strptime(cert["notAfter"],"%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    days=(expiry-datetime.datetime.now(datetime.timezone.utc)).total_seconds()/86400
    return {"host":host,"expires_at":expiry.isoformat(),"days_remaining":round(days,1),"expired":days<0,"checked":True}

FEATURE = {
    "id": "F069",
    "slug": 'tls_certificate_expiry',
    "name": 'TLS certificate expiry',
    "category": 'Diagnostics',
    "description": 'Read the expiry date of a TLS certificate with a short connection timeout.',
    "parameters": {'host': 'hostname', 'port': 'integer'},
    "run": run,
}
