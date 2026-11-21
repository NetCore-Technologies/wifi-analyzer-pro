"""F198: read-only assessment of supplied enterprise VPN and remote access profiles."""
from __future__ import annotations
from .enterprise_security_common import records, identifier, boolean, enum, bounded_int, finding, summarize

MAX_PROFILES = 256
PROTOCOLS = {"wireguard", "ipsec-ikev2", "openvpn", "ssl-vpn", "pptp", "l2tp", "unknown"}

def run(payload: dict) -> dict:
    profiles = records(payload, "profiles", MAX_PROFILES)
    findings = []
    for index, profile in enumerate(profiles):
        pid = identifier(profile.get("profile_id"), f"profiles[{index}].profile_id")
        identifier(profile.get("site_id", "unassigned"), f"profiles[{index}].site_id")
        protocol = enum(profile.get("protocol"), f"profiles[{index}].protocol", PROTOCOLS)
        if protocol in {"pptp", "l2tp"}:
            finding(findings, pid, "LEGACY_VPN_PROTOCOL", "critical", "violation",
                    f"The VPN profile uses legacy protocol {protocol.upper()}.",
                    "Migrate to IKEv2, WireGuard or OpenVPN with a reviewed cryptographic profile.")
        elif protocol == "unknown":
            finding(findings, pid, "VPN_PROTOCOL_UNKNOWN", "medium", "missing",
                    "VPN protocol was not supplied.", "Export the active remote-access protocol and version.")
        checks = (
            ("mfa_required", "VPN_MFA_NOT_REQUIRED", "critical", "Remote access MFA is explicitly not required.", "Require phishing-resistant MFA for every remote-access user."),
            ("device_posture_required", "VPN_DEVICE_POSTURE_NOT_REQUIRED", "high", "Device posture checks are explicitly not required.", "Require supported OS, endpoint protection and device compliance before tunnel admission."),
            ("certificate_auth_required", "VPN_CERTIFICATE_AUTH_NOT_REQUIRED", "medium", "Certificate-based device or user authentication is explicitly not required.", "Use per-device certificates or another managed strong identity factor."),
            ("admin_portal_mfa_required", "VPN_ADMIN_PORTAL_MFA_NOT_REQUIRED", "critical", "The VPN administration portal does not require MFA.", "Require MFA and restrict administration to a dedicated management network."),
            ("logging_enabled", "VPN_SECURITY_LOGGING_DISABLED", "medium", "Security event logging is explicitly disabled.", "Record authentication, policy, tunnel and administrator changes."),
            ("key_rotation_enabled", "VPN_KEY_ROTATION_DISABLED", "high", "VPN key or certificate rotation is explicitly disabled.", "Define rotation, expiry monitoring and revocation procedures."),
            ("split_tunnel_allowlist_enforced", "VPN_SPLIT_TUNNEL_UNRESTRICTED", "high", "Split tunnelling is enabled without an enforced destination allow-list.", "Use full tunnel or enforce explicit split-tunnel route allow-lists."),
            ("admin_access_restricted", "VPN_ADMIN_ACCESS_UNRESTRICTED", "critical", "VPN administration access is not restricted.", "Restrict admin access to management networks and named identities."),
        )
        for key, code, severity, description, recommendation in checks:
            state = boolean(profile.get(key), f"profiles[{index}].{key}")
            if state is False:
                finding(findings, pid, code, severity, "violation", description, recommendation)
            elif state is None:
                finding(findings, pid, code + "_UNKNOWN", "medium", "missing",
                        key.replace("_", " ").capitalize() + " evidence was not supplied.", recommendation)
        idle = profile.get("idle_timeout_minutes")
        if idle is None:
            finding(findings, pid, "VPN_IDLE_TIMEOUT_UNKNOWN", "low", "missing",
                    "Idle session timeout was not supplied.", "Configure a finite idle timeout suited to risk and usability.")
        else:
            idle = bounded_int(idle, f"profiles[{index}].idle_timeout_minutes", 1, 1440)
            if idle > 120:
                finding(findings, pid, "VPN_IDLE_TIMEOUT_TOO_LONG", "medium", "violation",
                        "The configured idle timeout exceeds two hours.", "Reduce idle session lifetime and require reauthentication for long-running access.")
        lifetime = profile.get("certificate_lifetime_days")
        if lifetime is not None:
            lifetime = bounded_int(lifetime, f"profiles[{index}].certificate_lifetime_days", 1, 3650)
            if lifetime > 397:
                finding(findings, pid, "VPN_CERTIFICATE_LIFETIME_LONG", "low", "violation",
                        "A VPN certificate lifetime exceeds 397 days.", "Shorten certificate lifetime and automate renewal/revocation.")
        elif profile.get("certificate_auth_required") is True:
            finding(findings, pid, "VPN_CERTIFICATE_LIFETIME_UNKNOWN", "low", "missing",
                    "VPN certificate lifetime was not supplied.", "Record certificate validity and renewal policy.")
    return summarize("F198", "Security", len(profiles), findings)

FEATURE = {
    "id": "F198", "slug": "enterprise_vpn_remote_access_audit",
    "name": "Enterprise VPN and remote access audit", "category": "Security",
    "description": "Audit supplied remote-access profiles for legacy protocols, MFA, device posture, certificate authentication, split tunnelling, administrator restrictions, logging, key rotation and session timeout.",
    "parameters": {"profiles": "up to 256 VPN profile records with identity, protocol and security-control evidence"},
    "run": run,
}
