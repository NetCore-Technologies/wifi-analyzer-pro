"""F196: offline, bounded review of supplied firewall rule-policy evidence."""
from __future__ import annotations
import ipaddress
import re
from .enterprise_security_common import records, identifier, boolean, enum, finding, summarize

MAX_FIREWALLS = 64
MAX_RULES = 512
ACTIONS = {"allow", "deny", "reject", "unknown"}
DIRECTIONS = {"inbound", "outbound", "forward", "management", "unknown"}
PROTOCOLS = {"any", "tcp", "udp", "icmp", "icmpv6", "gre", "esp", "unknown"}

def _cidr(value, field):
    if value in (None, "", "any", "0.0.0.0/0", "::/0"):
        return "any" if value not in (None, "") else "unknown"
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a CIDR string")
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as error:
        raise ValueError(f"{field} must be a valid CIDR network") from error

def _port(value, field):
    if value is None or value == "any":
        return "any"
    if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535:
        return str(value)
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}-[0-9]{1,5}", value):
        low, high = map(int, value.split("-"))
        if 1 <= low <= high <= 65535:
            return f"{low}-{high}"
    raise ValueError(f"{field} must be any, a port, or an ordered port range")

def run(payload: dict) -> dict:
    firewalls = records(payload, "firewalls", MAX_FIREWALLS)
    findings = []
    for index, firewall in enumerate(firewalls):
        fid = identifier(firewall.get("firewall_id"), f"firewalls[{index}].firewall_id")
        identifier(firewall.get("site_id", "unassigned"), f"firewalls[{index}].site_id")
        inbound = enum(firewall.get("default_inbound_action"), f"firewalls[{index}].default_inbound_action", ACTIONS)
        if inbound == "allow":
            finding(findings, fid, "DEFAULT_INBOUND_ALLOW", "critical", "violation",
                    "The supplied firewall policy allows inbound traffic by default.",
                    "Use default-deny inbound policy with explicit, reviewed allow rules.")
        elif inbound == "unknown":
            finding(findings, fid, "DEFAULT_INBOUND_UNKNOWN", "medium", "missing",
                    "Default inbound action was not supplied.", "Export the effective inbound default policy.")
        rules = firewall.get("rules")
        if rules is None:
            rules = []
            finding(findings, fid, "FIREWALL_RULE_INVENTORY_MISSING", "medium", "missing",
                    "Firewall rule inventory was not supplied.", "Export active ordered firewall rules and logging state.")
        if not isinstance(rules, list) or len(rules) > MAX_RULES:
            raise ValueError(f"firewalls[{index}].rules must contain no more than {MAX_RULES} records")
        signatures = {}
        for rindex, rule in enumerate(rules):
            prefix = f"firewalls[{index}].rules[{rindex}]"
            if not isinstance(rule, dict):
                raise ValueError(f"{prefix} must be an object")
            rid = identifier(rule.get("rule_id"), f"{prefix}.rule_id")
            action = enum(rule.get("action"), f"{prefix}.action", ACTIONS)
            direction = enum(rule.get("direction"), f"{prefix}.direction", DIRECTIONS)
            protocol = enum(rule.get("protocol", "any"), f"{prefix}.protocol", PROTOCOLS)
            source = _cidr(rule.get("source_cidr", "any"), f"{prefix}.source_cidr")
            destination = _cidr(rule.get("destination_cidr", "any"), f"{prefix}.destination_cidr")
            source_port = _port(rule.get("source_port", "any"), f"{prefix}.source_port")
            destination_port = _port(rule.get("destination_port", "any"), f"{prefix}.destination_port")
            enabled = boolean(rule.get("enabled", True), f"{prefix}.enabled")
            logging = boolean(rule.get("logging_enabled"), f"{prefix}.logging_enabled")
            management = boolean(rule.get("management_plane"), f"{prefix}.management_plane")
            if enabled is False:
                continue
            if action == "allow" and direction == "inbound" and source == "any" and destination == "any" and protocol == "any" and destination_port == "any":
                finding(findings, fid, "INBOUND_ANY_ANY_ALLOW", "critical", "violation",
                        "An enabled inbound rule permits any source to any destination and service.",
                        "Replace broad access with narrow source, destination, protocol and port allow rules.")
            if action == "allow" and management is True and source == "any":
                finding(findings, fid, "MANAGEMENT_INGRESS_OPEN", "critical", "violation",
                        "A management-plane allow rule has an unrestricted source.",
                        "Restrict management-plane access to approved admin subnets and jump hosts.")
            if logging is False:
                finding(findings, fid, "FIREWALL_RULE_LOGGING_DISABLED", "low", "violation",
                        "An enabled firewall rule has logging explicitly disabled.",
                        "Enable privacy-aware logging for security-relevant allow and deny decisions.")
            elif logging is None:
                finding(findings, fid, "FIREWALL_RULE_LOGGING_UNKNOWN", "low", "missing",
                        "Logging state was not supplied for an enabled firewall rule.",
                        "Verify rule logging and central log forwarding.")
            signature = (direction, action, protocol, source, destination, source_port, destination_port)
            if signature in signatures:
                finding(findings, fid, "DUPLICATE_FIREWALL_RULE", "medium", "violation",
                        f"Enabled rules {signatures[signature]} and {rid} have identical match and action fields.",
                        "Remove duplicate rules after checking policy references and counters.")
            else:
                signatures[signature] = rid
            if direction == "unknown" or action == "unknown":
                finding(findings, fid, "FIREWALL_RULE_POLICY_UNKNOWN", "medium", "missing",
                        f"Rule {rid} has incomplete direction or action evidence.",
                        "Export effective rule direction and action.")
    return summarize("F196", "Security", len(firewalls), findings, {
        "limitations": ["This audit does not simulate vendor-specific ACL ordering, NAT, state tables or implicit policy. It reports only explicit broad matches and exact duplicates."]
    })

FEATURE = {
    "id": "F196", "slug": "enterprise_firewall_policy_audit",
    "name": "Enterprise firewall policy audit", "category": "Security",
    "description": "Review supplied inbound/outbound firewall defaults and rules for broad any/any access, exposed management ingress, duplicate policies and missing logging. Does not connect to firewalls or claim vendor-specific ACL shadowing.",
    "parameters": {"firewalls": "up to 64 firewall records with default actions and up to 512 ordered rules each"},
    "run": run,
}
