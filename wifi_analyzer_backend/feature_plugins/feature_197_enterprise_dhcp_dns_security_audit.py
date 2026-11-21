"""F197: evidence-based DHCP and DNS infrastructure security audit."""
from __future__ import annotations
import ipaddress
from .enterprise_security_common import records, identifier, boolean, enum, finding, summarize

MAX_SERVICES = 256
MAX_SCOPES = 128
DNS_TRANSPORTS = {"dot", "doh", "doq", "plain", "unknown"}

def run(payload: dict) -> dict:
    services = records(payload, "services", MAX_SERVICES)
    findings = []
    scope_records = []
    for index, service in enumerate(services):
        sid = identifier(service.get("service_id"), f"services[{index}].service_id")
        site = identifier(service.get("site_id", "unassigned"), f"services[{index}].site_id")
        role = enum(service.get("role"), f"services[{index}].role", {"dhcp", "dns", "dhcp-dns", "unknown"})
        enabled = boolean(service.get("enabled"), f"services[{index}].enabled")
        if enabled is None:
            finding(findings, sid, "SERVICE_ENABLED_STATE_UNKNOWN", "low", "missing",
                    "Service enabled state was not supplied.", "Export service state from the DHCP/DNS server.")
        if role in {"dhcp", "dhcp-dns"}:
            for key, code, description, recommendation in (
                ("dhcp_snooping_enabled", "DHCP_SNOOPING_DISABLED", "DHCP snooping is explicitly disabled.", "Enable DHCP snooping and trust only verified server-facing ports."),
                ("rogue_dhcp_detection_enabled", "ROGUE_DHCP_DETECTION_DISABLED", "Rogue DHCP detection is explicitly disabled.", "Enable rogue DHCP detection and alert on unexpected offers."),
                ("trusted_dhcp_server_inventory_complete", "DHCP_TRUSTED_SERVER_INVENTORY_INCOMPLETE", "The authorised DHCP server inventory is explicitly incomplete.", "Maintain an allow-listed DHCP server inventory and reconcile switch trust configuration."),
            ):
                state = boolean(service.get(key), f"services[{index}].{key}")
                if state is False:
                    finding(findings, sid, code, "high", "violation", description, recommendation)
                elif state is None:
                    finding(findings, sid, code + "_UNKNOWN", "medium", "missing",
                            description.replace("explicitly disabled", "state was not supplied").replace("explicitly incomplete", "completeness evidence was not supplied"), recommendation)
            scopes = service.get("dhcp_scopes")
            if scopes is None:
                scopes = []
                finding(findings, sid, "DHCP_SCOPE_INVENTORY_MISSING", "medium", "missing",
                        "DHCP scope inventory was not supplied.", "Export active DHCP scopes and exclusions.")
            if not isinstance(scopes, list) or len(scopes) > MAX_SCOPES:
                raise ValueError(f"services[{index}].dhcp_scopes must contain no more than {MAX_SCOPES} entries")
            for scope_index, scope in enumerate(scopes):
                prefix = f"services[{index}].dhcp_scopes[{scope_index}]"
                if not isinstance(scope, dict):
                    raise ValueError(f"{prefix} must be an object")
                scope_id = identifier(scope.get("scope_id"), f"{prefix}.scope_id")
                cidr = scope.get("cidr")
                if not isinstance(cidr, str):
                    raise ValueError(f"{prefix}.cidr must be a CIDR")
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError as error:
                    raise ValueError(f"{prefix}.cidr must be a valid CIDR") from error
                scope_records.append((sid, site, scope_id, network))
            option82 = boolean(service.get("option82_enabled"), f"services[{index}].option82_enabled")
            if option82 is False:
                finding(findings, sid, "DHCP_OPTION82_DISABLED", "low", "violation",
                        "DHCP Option 82 relay-agent information is disabled.",
                        "Enable and validate Option 82 where relay topology and privacy policy require it.")
        if role in {"dns", "dhcp-dns"}:
            dnssec = boolean(service.get("dnssec_validation_enabled"), f"services[{index}].dnssec_validation_enabled")
            transport = enum(service.get("upstream_transport"), f"services[{index}].upstream_transport", DNS_TRANSPORTS)
            forwarders = service.get("approved_forwarders")
            if forwarders is None:
                finding(findings, sid, "DNS_FORWARDER_INVENTORY_MISSING", "medium", "missing",
                        "Approved upstream DNS forwarder inventory was not supplied.", "Maintain an allow-listed upstream resolver inventory.")
            elif not isinstance(forwarders, list) or len(forwarders) > 32 or any(not isinstance(item, str) or not item.strip() for item in forwarders):
                raise ValueError(f"services[{index}].approved_forwarders must contain up to 32 non-empty names")
            if dnssec is False:
                finding(findings, sid, "DNSSEC_VALIDATION_DISABLED", "high", "violation",
                        "DNSSEC validation is explicitly disabled.", "Enable DNSSEC validation and monitor validation failures.")
            elif dnssec is None:
                finding(findings, sid, "DNSSEC_VALIDATION_UNKNOWN", "medium", "missing",
                        "DNSSEC validation state was not supplied.", "Verify DNSSEC validation is active on the recursive resolver.")
            if transport == "plain":
                finding(findings, sid, "DNS_UPSTREAM_UNENCRYPTED", "medium", "violation",
                        "Upstream DNS transport is explicitly unencrypted.", "Use DNS-over-TLS, DNS-over-HTTPS or DNS-over-QUIC to a trusted resolver.")
            elif transport == "unknown":
                finding(findings, sid, "DNS_UPSTREAM_TRANSPORT_UNKNOWN", "low", "missing",
                        "Upstream DNS transport was not supplied.", "Verify encrypted upstream DNS transport.")
            restriction = boolean(service.get("outbound_dns_restricted"), f"services[{index}].outbound_dns_restricted")
            if restriction is False:
                finding(findings, sid, "OUTBOUND_DNS_UNRESTRICTED", "high", "violation",
                        "Clients can send DNS to arbitrary external resolvers.", "Restrict outbound DNS to approved resolvers and block direct DNS bypass.")
            elif restriction is None:
                finding(findings, sid, "OUTBOUND_DNS_RESTRICTION_UNKNOWN", "medium", "missing",
                        "Outbound DNS restriction evidence was not supplied.", "Verify egress policy for UDP/TCP 53 and approved encrypted resolver destinations.")
    overlap_count = 0
    for position, left in enumerate(scope_records):
        for right in scope_records[position + 1:]:
            if left[1] == right[1] and left[3].version == right[3].version and left[3].overlaps(right[3]):
                overlap_count += 1
                finding(findings, left[0], "DHCP_SCOPE_OVERLAP", "high", "violation",
                        f"DHCP scopes {left[2]} and {right[2]} overlap within site {left[1]}.",
                        "Correct overlapping pools or document an intentional shared-scope/failover design.")
    return summarize("F197", "Security", len(services), findings, {"overlapping_scope_pair_count": overlap_count})

FEATURE = {
    "id": "F197", "slug": "enterprise_dhcp_dns_security_audit",
    "name": "Enterprise DHCP and DNS security audit", "category": "Security",
    "description": "Review DHCP snooping, rogue-server detection, trusted server inventories, Option 82, overlapping scopes, DNSSEC and encrypted upstream resolvers from supplied evidence only.",
    "parameters": {"services": "up to 256 DHCP/DNS service records with bounded scopes and resolver configuration evidence"},
    "run": run,
}
