"""F195: offline audit of supplied enterprise switch management-plane evidence."""
from __future__ import annotations
from .enterprise_security_common import records, identifier, boolean, enum, bounded_int, finding, summarize

MAX_SWITCHES = 256
PROTOCOLS = {"ssh-v2", "https", "snmpv3", "snmpv2c", "snmpv1", "telnet", "http", "unknown"}

def run(payload: dict) -> dict:
    switches = records(payload, "switches", MAX_SWITCHES)
    findings = []
    for index, switch in enumerate(switches):
        sid = identifier(switch.get("switch_id"), f"switches[{index}].switch_id")
        identifier(switch.get("site_id", "unassigned"), f"switches[{index}].site_id")
        protocols = switch.get("management_protocols")
        if protocols is None:
            protocols = []
            finding(findings, sid, "MANAGEMENT_PROTOCOL_EVIDENCE_MISSING", "medium", "missing",
                    "Management protocol inventory was not supplied.",
                    "Export enabled management services from the switch configuration.")
        if not isinstance(protocols, list) or len(protocols) > 16:
            raise ValueError(f"switches[{index}].management_protocols must contain no more than 16 entries")
        normalized = [
            enum(protocol, f"switches[{index}].management_protocols[{pindex}]", PROTOCOLS)
            for pindex, protocol in enumerate(protocols)
        ]
        if "telnet" in normalized:
            finding(findings, sid, "TELNET_ENABLED", "critical", "violation",
                    "Telnet is enabled on the switch management plane.",
                    "Disable Telnet and use SSH version 2 or authenticated HTTPS management.")
        if "http" in normalized:
            finding(findings, sid, "HTTP_MANAGEMENT_ENABLED", "high", "violation",
                    "Unencrypted HTTP management is enabled.",
                    "Disable HTTP and require HTTPS with a trusted certificate.")
        if {"snmpv1", "snmpv2c"} & set(normalized):
            finding(findings, sid, "LEGACY_SNMP_ENABLED", "high", "violation",
                    "SNMPv1 or SNMPv2c is enabled.",
                    "Migrate to SNMPv3 authPriv and rotate legacy community strings.")
        if protocols and not ({"ssh-v2", "https"} & set(normalized)):
            finding(findings, sid, "SECURE_MANAGEMENT_TRANSPORT_MISSING", "high", "violation",
                    "No supported secure management transport was observed.",
                    "Enable SSHv2 and/or HTTPS and disable legacy management services.")
        snmp_privacy = boolean(switch.get("snmpv3_privacy_enabled"), f"switches[{index}].snmpv3_privacy_enabled")
        if "snmpv3" in normalized and snmp_privacy is False:
            finding(findings, sid, "SNMPV3_PRIVACY_DISABLED", "high", "violation",
                    "SNMPv3 privacy encryption is explicitly disabled.",
                    "Require SNMPv3 authentication and privacy encryption.")
        elif "snmpv3" in normalized and snmp_privacy is None:
            finding(findings, sid, "SNMPV3_PRIVACY_UNKNOWN", "medium", "missing",
                    "SNMPv3 privacy configuration was not supplied.",
                    "Verify SNMPv3 uses authentication and privacy encryption.")
        checks = (
            ("aaa_enabled", "AAA_DISABLED", "critical", "Central AAA is explicitly disabled.", "Enable central AAA and test break-glass recovery."),
            ("mfa_enabled", "ADMIN_MFA_DISABLED", "high", "Administrator MFA is explicitly disabled.", "Require phishing-resistant MFA for administrative access."),
            ("management_acl_restricted", "MANAGEMENT_ACL_UNRESTRICTED", "critical", "Management access is not restricted by an ACL.", "Restrict management access to approved management networks and jump hosts."),
            ("default_accounts_disabled", "DEFAULT_ACCOUNTS_ENABLED", "high", "Factory administrator accounts remain enabled.", "Disable factory accounts and use named, auditable administrator identities."),
            ("encrypted_config_backup", "CONFIG_BACKUP_NOT_ENCRYPTED", "high", "Configuration backup encryption is explicitly disabled.", "Encrypt configuration backups and protect backup keys separately."),
            ("syslog_tls_enabled", "SYSLOG_TLS_DISABLED", "medium", "Remote syslog transport is not protected by TLS.", "Forward audit logs over authenticated TLS."),
            ("authenticated_ntp_enabled", "AUTHENTICATED_NTP_DISABLED", "medium", "Authenticated time synchronisation is explicitly disabled.", "Use trusted authenticated time sources and monitor clock drift."),
        )
        for key, code, severity, description, recommendation in checks:
            state = boolean(switch.get(key), f"switches[{index}].{key}")
            if state is False:
                finding(findings, sid, code, severity, "violation", description, recommendation)
            elif state is None:
                finding(findings, sid, code + "_UNKNOWN", "low", "missing",
                        key.replace("_", " ").capitalize() + " evidence was not supplied.", recommendation)
        ssh = enum(switch.get("ssh_protocol_version"), f"switches[{index}].ssh_protocol_version", {"1", "2", "unknown"})
        if ssh == "1":
            finding(findings, sid, "SSH_V1_ENABLED", "critical", "violation",
                    "SSH protocol version 1 is configured.", "Disable SSHv1 and require SSHv2.")
        elif ssh == "unknown" and "ssh-v2" not in normalized:
            finding(findings, sid, "SSH_VERSION_UNKNOWN", "low", "missing",
                    "The SSH protocol version was not supplied.", "Verify the switch accepts SSHv2 only.")
        bounded_int(switch.get("stale_local_admin_count", 0), f"switches[{index}].stale_local_admin_count", 0, 10000)
    return summarize("F195", "Security", len(switches), findings)

FEATURE = {
    "id": "F195", "slug": "enterprise_switch_management_audit",
    "name": "Enterprise switch management-plane audit", "category": "Security",
    "description": "Audit supplied switch evidence for secure management transports, SNMPv3 privacy, AAA/MFA, management ACLs, default accounts, encrypted backups, TLS syslog and authenticated time. Reports missing evidence separately and never returns secrets or management addresses.",
    "parameters": {"switches": "up to 256 switch records with management protocols and security-control evidence"},
    "run": run,
}
