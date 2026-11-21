"""F194: evidence-aware security posture audit for office WLAN profiles.

The audit is offline and read-only. It evaluates supplied configuration snapshots,
never returns SSIDs, RADIUS host addresses or secret material, and distinguishes
missing evidence from observed policy violations.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter

MAX_PROFILES = 1024
MAX_RADIUS_SERVERS = 16
MAX_EAP_METHODS = 12
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

SECURITY_MODES = {
    "open", "wep", "wpa", "wpa2-personal", "wpa3-personal",
    "wpa2-enterprise", "wpa3-enterprise",
    "wpa2-wpa3-personal", "wpa2-wpa3-enterprise", "unknown",
}
ENTERPRISE_MODES = {"wpa2-enterprise", "wpa3-enterprise", "wpa2-wpa3-enterprise"}
SECURITY_LEVEL = {
    "open": 0, "wep": 0, "wpa": 1, "wpa2-personal": 2,
    "wpa3-personal": 3, "wpa2-enterprise": 4,
    "wpa2-wpa3-enterprise": 4, "wpa3-enterprise": 5,
}
PMF_STATES = {"required", "capable", "optional", "disabled", "unknown"}
PURPOSES = {"corporate", "guest", "iot", "management", "other"}
EAP_METHODS = {
    "eap-tls", "eap-peap-mschapv2", "eap-ttls-pap",
    "eap-ttls-mschapv2", "eap-fast", "eap-pwd",
}
SEVERITY_WEIGHTS = {"critical": 50, "high": 25, "medium": 10, "low": 3, "info": 0}
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string identifier")
    cleaned = value.strip()
    if not IDENTIFIER.fullmatch(cleaned):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return cleaned


def _boolean(value: object, field: str, default: bool | None = None) -> bool | None:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer from {minimum} to {maximum}")
    return value


def _security_mode(value: object, field: str) -> str:
    if value is None or value == "":
        return "unknown"
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a security-mode string")
    token = re.sub(r"[^a-z0-9]+", "", value.strip().lower())
    aliases = {
        "open": "open", "none": "open", "unencrypted": "open",
        "wep": "wep", "wpa": "wpa",
        "wpa2personal": "wpa2-personal", "wpa2psk": "wpa2-personal",
        "wpa3personal": "wpa3-personal", "wpa3sae": "wpa3-personal",
        "wpa2enterprise": "wpa2-enterprise", "wpa2eap": "wpa2-enterprise",
        "wpa3enterprise": "wpa3-enterprise", "wpa3eap": "wpa3-enterprise",
        "wpa2wpa3personal": "wpa2-wpa3-personal",
        "wpa2wpa3enterprise": "wpa2-wpa3-enterprise",
        "unknown": "unknown",
    }
    result = aliases.get(token)
    if result not in SECURITY_MODES:
        raise ValueError(f"{field} is not a supported WLAN security mode")
    return result


def _pmf_state(value: object, field: str) -> str:
    if value is None or value == "":
        return "unknown"
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a PMF state string")
    state = value.strip().lower()
    aliases = {"optional": "optional", "capable": "capable", "required": "required",
               "disabled": "disabled", "not_required": "optional", "unknown": "unknown"}
    state = aliases.get(state, state)
    if state not in PMF_STATES:
        raise ValueError(f"{field} must be one of {sorted(PMF_STATES)}")
    return state


def _eap_method(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty EAP method")
    token = re.sub(r"[^a-z0-9]+", "", value.strip().lower())
    aliases = {
        "eaptls": "eap-tls", "tls": "eap-tls",
        "peap": "eap-peap-mschapv2", "peapmschapv2": "eap-peap-mschapv2",
        "eappeap": "eap-peap-mschapv2", "eappeapmschapv2": "eap-peap-mschapv2",
        "eapttlspap": "eap-ttls-pap", "ttlspap": "eap-ttls-pap",
        "eapttlsmschapv2": "eap-ttls-mschapv2", "ttlsmschapv2": "eap-ttls-mschapv2",
        "eapfast": "eap-fast", "fast": "eap-fast",
        "eappwd": "eap-pwd", "pwd": "eap-pwd",
    }
    result = aliases.get(token)
    if result not in EAP_METHODS:
        raise ValueError(f"{field} is not a supported EAP method")
    return result


def _host_address(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must contain a RADIUS server address")
    host = value.strip().rstrip(".")
    if len(host) > 253 or any(ord(char) < 33 or ord(char) > 126 for char in host):
        raise ValueError(f"{field} must be a valid IP address or DNS hostname")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        labels = host.split(".")
        if not labels or any(not HOST_LABEL.fullmatch(label) for label in labels):
            raise ValueError(f"{field} must be a valid IP address or DNS hostname")
        return host.lower()


def _policy(payload: dict) -> dict:
    raw = payload.get("policy", {})
    if not isinstance(raw, dict):
        raise ValueError("policy must be an object")
    minimum = _security_mode(raw.get("minimum_corporate_security", "wpa2-enterprise"), "policy.minimum_corporate_security")
    if minimum not in {"wpa2-enterprise", "wpa3-enterprise"}:
        raise ValueError("policy.minimum_corporate_security must be WPA2-Enterprise or WPA3-Enterprise")

    raw_methods = raw.get("allowed_eap_methods", ["eap-tls"])
    if not isinstance(raw_methods, list) or not raw_methods or len(raw_methods) > MAX_EAP_METHODS:
        raise ValueError(f"policy.allowed_eap_methods must contain 1 to {MAX_EAP_METHODS} methods")
    allowed_methods = [_eap_method(value, f"policy.allowed_eap_methods[{index}]") for index, value in enumerate(raw_methods)]
    if len(set(allowed_methods)) != len(allowed_methods):
        raise ValueError("policy.allowed_eap_methods must be unique")

    minimum_radius = _integer(raw.get("minimum_radius_servers", 2), "policy.minimum_radius_servers", 1, 8)
    bool_defaults = {
        "require_pmf": True,
        "require_radius_shared_secret": True,
        "require_server_certificate_validation": True,
        "require_client_certificate": True,
        "require_guest_vlan": True,
        "require_guest_client_isolation": True,
        "require_guest_firewall_isolation": True,
        "require_guest_captive_portal_for_open": True,
        "require_iot_segmentation": True,
        "require_management_access_restricted": True,
        "require_wps_disabled": True,
    }
    result = {
        "minimum_corporate_security": minimum,
        "allowed_eap_methods": allowed_methods,
        "minimum_radius_servers": minimum_radius,
    }
    for key, default in bool_defaults.items():
        result[key] = _boolean(raw.get(key), f"policy.{key}", default)
    return result


def _radius_inventory(value: object, field: str) -> tuple[int, list[bool | None]]:
    if not isinstance(value, list) or len(value) > MAX_RADIUS_SERVERS:
        raise ValueError(f"{field} must be a list containing no more than {MAX_RADIUS_SERVERS} servers")
    addresses = set()
    server_ids = set()
    secret_states: list[bool | None] = []
    for index, server in enumerate(value):
        item_field = f"{field}[{index}]"
        if not isinstance(server, dict):
            raise ValueError(f"{item_field} must be an object")
        address = _host_address(server.get("address", server.get("host")), f"{item_field}.address")
        server_id = server.get("server_id")
        if server_id is not None:
            server_id = _identifier(server_id, f"{item_field}.server_id")
            if server_id in server_ids:
                raise ValueError(f"{field} server_id values must be unique")
            server_ids.add(server_id)
        port = server.get("auth_port", server.get("port"))
        if port is not None:
            _integer(port, f"{item_field}.auth_port", 1, 65535)
        secret_states.append(_boolean(server.get("shared_secret_configured"), f"{item_field}.shared_secret_configured"))
        addresses.add(address)
    return len(addresses), secret_states


def _finding(
    findings: list[dict],
    profile_findings: list[dict],
    profile_id: str,
    site_id: str,
    code: str,
    severity: str,
    message: str,
    evidence_state: str = "violation",
) -> None:
    item = {
        "profile_id": profile_id,
        "site_id": site_id,
        "code": code,
        "severity": severity,
        "evidence_state": evidence_state,
        "message": message,
    }
    findings.append(item)
    profile_findings.append(item)


def run(payload: dict) -> dict:
    """Audit bounded controller/configuration evidence without returning credentials or server addresses."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    policy = _policy(payload)
    profiles = payload.get("profiles", [])
    if not isinstance(profiles, list) or len(profiles) > MAX_PROFILES:
        raise ValueError(f"profiles must be a list containing no more than {MAX_PROFILES} records")

    findings: list[dict] = []
    profile_results: list[dict] = []
    profile_ids = set()
    severity_counts = Counter()
    status_counts = Counter()
    risk_total = 0
    enabled_count = 0
    gap_count = 0
    violation_count = 0

    for index, profile in enumerate(profiles):
        field = f"profiles[{index}]"
        if not isinstance(profile, dict):
            raise ValueError(f"{field} must be an object")
        profile_id = _identifier(profile.get("profile_id"), f"{field}.profile_id")
        if profile_id in profile_ids:
            raise ValueError("profile_id values must be unique")
        profile_ids.add(profile_id)
        site_id = "unassigned" if profile.get("site_id") is None else _identifier(profile.get("site_id"), f"{field}.site_id")
        purpose = profile.get("purpose", "other")
        if not isinstance(purpose, str) or purpose.strip().lower() not in PURPOSES:
            raise ValueError(f"{field}.purpose must be one of {sorted(PURPOSES)}")
        purpose = purpose.strip().lower()
        enabled = _boolean(profile.get("enabled"), f"{field}.enabled")
        security = _security_mode(profile.get("security_mode"), f"{field}.security_mode")
        pmf = _pmf_state(profile.get("pmf"), f"{field}.pmf")
        raw_eap = profile.get("eap_methods", [])
        if not isinstance(raw_eap, list) or len(raw_eap) > MAX_EAP_METHODS:
            raise ValueError(f"{field}.eap_methods must be a list containing no more than {MAX_EAP_METHODS} methods")
        eap_methods = [_eap_method(value, f"{field}.eap_methods[{method_index}]") for method_index, value in enumerate(raw_eap)]
        if len(set(eap_methods)) != len(eap_methods):
            raise ValueError(f"{field}.eap_methods must be unique")

        ieee8021x = _boolean(profile.get("ieee8021x_enabled"), f"{field}.ieee8021x_enabled")
        server_cert_validation = _boolean(profile.get("validate_server_certificate"), f"{field}.validate_server_certificate")
        client_cert_required = _boolean(profile.get("client_certificate_required"), f"{field}.client_certificate_required")
        wps_enabled = _boolean(profile.get("wps_enabled"), f"{field}.wps_enabled")
        vlan_value = profile.get("vlan_id")
        vlan_id = None if vlan_value is None else _integer(vlan_value, f"{field}.vlan_id", 1, 4094)
        client_isolation = _boolean(profile.get("client_isolation"), f"{field}.client_isolation")
        firewall_isolation = _boolean(profile.get("firewall_isolation"), f"{field}.firewall_isolation")
        captive_portal = _boolean(profile.get("captive_portal_enabled"), f"{field}.captive_portal_enabled")
        management_restricted = _boolean(profile.get("management_access_restricted"), f"{field}.management_access_restricted")

        radius_count, radius_secret_states = _radius_inventory(profile.get("radius_servers", []), f"{field}.radius_servers")
        profile_findings: list[dict] = []
        profile_risk = 0

        def add(code: str, severity: str, message: str, evidence_state: str = "violation") -> None:
            nonlocal profile_risk
            _finding(findings, profile_findings, profile_id, site_id, code, severity, message, evidence_state)
            if evidence_state == "violation":
                profile_risk += SEVERITY_WEIGHTS[severity]

        if enabled is False:
            profile_status = "disabled"
        else:
            enabled_count += 1
            if enabled is None:
                add("PROFILE_ENABLEMENT_UNKNOWN", "medium", "The profile's enabled state was not supplied.", "missing")

            if security == "unknown":
                add("SECURITY_MODE_UNKNOWN", "medium", "The profile security mode is unknown; provide a current controller observation.", "missing")

            if purpose in {"corporate", "management"}:
                if security != "unknown" and security not in ENTERPRISE_MODES:
                    add("CORPORATE_REQUIRES_ENTERPRISE_AUTH", "critical", "Corporate and management WLANs must use enterprise authentication backed by 802.1X.")
                elif security in ENTERPRISE_MODES:
                    minimum_level = SECURITY_LEVEL[policy["minimum_corporate_security"]]
                    if SECURITY_LEVEL[security] < minimum_level:
                        add("CORPORATE_SECURITY_BELOW_POLICY", "high", "The enterprise security mode is below the configured corporate minimum.")
                    if ieee8021x is False:
                        add("IEEE8021X_DISABLED", "critical", "Enterprise WLAN security is configured without 802.1X being enabled.")
                    elif ieee8021x is None:
                        add("IEEE8021X_EVIDENCE_MISSING", "medium", "802.1X enablement was not supplied for this enterprise WLAN.", "missing")

                    if not eap_methods:
                        add("EAP_METHOD_EVIDENCE_MISSING", "medium", "The configured EAP method list was not supplied.", "missing")
                    else:
                        disallowed = sorted(set(eap_methods) - set(policy["allowed_eap_methods"]))
                        if disallowed:
                            add("EAP_METHOD_NOT_ALLOWED", "high", "One or more configured EAP methods are not permitted by the selected policy.")

                    if policy["require_server_certificate_validation"]:
                        if server_cert_validation is False:
                            add("RADIUS_SERVER_CERT_VALIDATION_DISABLED", "high", "RADIUS server certificate validation is disabled.")
                        elif server_cert_validation is None:
                            add("RADIUS_SERVER_CERT_VALIDATION_UNKNOWN", "medium", "RADIUS server certificate validation state was not supplied.", "missing")

                    if "eap-tls" in eap_methods and policy["require_client_certificate"]:
                        if client_cert_required is False:
                            add("EAP_TLS_CLIENT_CERT_NOT_REQUIRED", "high", "EAP-TLS is configured without requiring a client certificate.")
                        elif client_cert_required is None:
                            add("EAP_TLS_CLIENT_CERT_UNKNOWN", "medium", "EAP-TLS client-certificate enforcement was not supplied.", "missing")

                    if radius_count == 0:
                        add("RADIUS_SERVERS_MISSING", "critical", "No RADIUS server records were supplied for an enterprise WLAN.")
                    elif radius_count < policy["minimum_radius_servers"]:
                        add("RADIUS_REDUNDANCY_INSUFFICIENT", "high", "The number of distinct RADIUS servers is below the configured redundancy minimum.")

                    if policy["require_radius_shared_secret"]:
                        if any(state is False for state in radius_secret_states):
                            add("RADIUS_SHARED_SECRET_NOT_CONFIGURED", "high", "At least one RADIUS server is explicitly marked without a configured shared secret.")
                        elif radius_secret_states and any(state is None for state in radius_secret_states):
                            add("RADIUS_SECRET_EVIDENCE_MISSING", "medium", "Shared-secret configuration state is unknown for one or more RADIUS servers.", "missing")

                if purpose == "management" and policy["require_management_access_restricted"]:
                    if management_restricted is False:
                        add("MANAGEMENT_ACCESS_EXPOSED", "critical", "Management WLAN access is not restricted by the supplied policy evidence.")
                    elif management_restricted is None:
                        add("MANAGEMENT_ACCESS_EVIDENCE_MISSING", "medium", "Management WLAN access restrictions were not supplied.", "missing")

            if policy["require_pmf"]:
                if pmf == "unknown":
                    add("PMF_EVIDENCE_MISSING", "medium", "Protected Management Frames state was not supplied.", "missing")
                elif pmf != "required":
                    add("PMF_NOT_REQUIRED", "high", "Protected Management Frames are not required by this WLAN profile.")

            if purpose == "guest":
                if security == "open" and policy["require_guest_captive_portal_for_open"]:
                    if captive_portal is False:
                        add("GUEST_OPEN_WITHOUT_CAPTIVE_PORTAL", "high", "The open guest WLAN has no captive portal configured in the supplied evidence.")
                    elif captive_portal is None:
                        add("GUEST_PORTAL_EVIDENCE_MISSING", "medium", "Captive-portal state was not supplied for the open guest WLAN.", "missing")
                if policy["require_guest_vlan"]:
                    if vlan_id is None:
                        add("GUEST_VLAN_EVIDENCE_MISSING", "medium", "Guest VLAN assignment was not supplied.", "missing")
                if policy["require_guest_client_isolation"]:
                    if client_isolation is False:
                        add("GUEST_CLIENT_ISOLATION_DISABLED", "high", "Guest clients are not isolated from one another.")
                    elif client_isolation is None:
                        add("GUEST_CLIENT_ISOLATION_UNKNOWN", "medium", "Guest client-isolation state was not supplied.", "missing")
                if policy["require_guest_firewall_isolation"]:
                    if firewall_isolation is False:
                        add("GUEST_FIREWALL_ISOLATION_DISABLED", "critical", "Guest-to-internal firewall isolation is explicitly disabled.")
                    elif firewall_isolation is None:
                        add("GUEST_FIREWALL_ISOLATION_UNKNOWN", "medium", "Guest firewall-isolation state was not supplied.", "missing")

            if purpose == "iot" and policy["require_iot_segmentation"]:
                if vlan_id is None:
                    add("IOT_VLAN_EVIDENCE_MISSING", "medium", "IoT VLAN assignment was not supplied.", "missing")
                if client_isolation is False:
                    add("IOT_CLIENT_ISOLATION_DISABLED", "high", "IoT clients are not isolated from one another.")
                elif client_isolation is None:
                    add("IOT_CLIENT_ISOLATION_UNKNOWN", "medium", "IoT client-isolation state was not supplied.", "missing")
                if firewall_isolation is False:
                    add("IOT_FIREWALL_ISOLATION_DISABLED", "high", "IoT-to-internal firewall isolation is explicitly disabled.")
                elif firewall_isolation is None:
                    add("IOT_FIREWALL_ISOLATION_UNKNOWN", "medium", "IoT firewall-isolation state was not supplied.", "missing")

            if purpose not in {"guest"} and security in {"open", "wep", "wpa"}:
                add("LEGACY_OR_UNENCRYPTED_SECURITY", "high", "The WLAN uses open or obsolete link security.")
            if wps_enabled is True and policy["require_wps_disabled"]:
                add("WPS_ENABLED", "high", "Wi-Fi Protected Setup is enabled; disable it unless a documented exception exists.")
            elif wps_enabled is None and policy["require_wps_disabled"]:
                add("WPS_STATE_UNKNOWN", "low", "WPS state was not supplied for this profile.", "missing")

            gap_count += sum(1 for item in profile_findings if item["evidence_state"] == "missing")
            violation_count += sum(1 for item in profile_findings if item["evidence_state"] == "violation")
            if any(item["evidence_state"] == "violation" for item in profile_findings):
                profile_status = "non_compliant"
            elif any(item["evidence_state"] == "missing" for item in profile_findings):
                profile_status = "evidence_incomplete"
            else:
                profile_status = "compliant"
            risk_total += min(100, profile_risk)

        status_counts[profile_status] += 1
        profile_results.append({
            "profile_id": profile_id,
            "site_id": site_id,
            "purpose": purpose,
            "enabled": enabled,
            "security_mode": security,
            "pmf_state": pmf,
            "eap_methods": eap_methods,
            "radius_server_count": radius_count,
            "status": profile_status,
            "observed_risk_score": 0 if enabled is False else min(100, profile_risk),
            "finding_count": len(profile_findings),
            "finding_codes": [item["code"] for item in profile_findings],
        })

    for item in findings:
        severity_counts[item["severity"]] += 1

    assessed = status_counts["compliant"] + sum(
        1 for item in profile_results
        if item["status"] == "non_compliant"
        and not any(
            finding["profile_id"] == item["profile_id"] and finding["evidence_state"] == "missing"
            for finding in findings
        )
    )
    fully_compliant = sum(
        1 for item in profile_results
        if item["status"] == "compliant" and item["enabled"] is not False
    )
    compliance_pct = round(fully_compliant / assessed * 100, 2) if assessed else None
    observed_risk = round(risk_total / enabled_count, 2) if enabled_count else None

    recommendation_by_code = {
        "CORPORATE_REQUIRES_ENTERPRISE_AUTH": "Move corporate and management WLANs to 802.1X-backed WPA2-Enterprise or WPA3-Enterprise.",
        "CORPORATE_SECURITY_BELOW_POLICY": "Upgrade enterprise WLAN security to the configured minimum and validate client compatibility.",
        "IEEE8021X_DISABLED": "Enable 802.1X and verify the managed RADIUS authentication path.",
        "PMF_NOT_REQUIRED": "Require Protected Management Frames where supported by the client estate.",
        "EAP_METHOD_NOT_ALLOWED": "Replace disallowed EAP methods with an approved method, preferably certificate-based EAP-TLS.",
        "RADIUS_SERVERS_MISSING": "Configure RADIUS authentication servers and verify reachability from every WLAN controller.",
        "RADIUS_REDUNDANCY_INSUFFICIENT": "Provide the configured minimum number of distinct RADIUS servers or document an approved high-availability design.",
        "RADIUS_SHARED_SECRET_NOT_CONFIGURED": "Configure unique, high-entropy RADIUS shared secrets and store them in the controller's protected credential store.",
        "RADIUS_SERVER_CERT_VALIDATION_DISABLED": "Enable RADIUS server certificate and trusted-name validation to reduce credential interception risk.",
        "EAP_TLS_CLIENT_CERT_NOT_REQUIRED": "Require managed client certificates for EAP-TLS and validate their issuance and revocation lifecycle.",
        "GUEST_VLAN_EVIDENCE_MISSING": "Verify that guest WLAN traffic is mapped to a dedicated guest VLAN.",
        "GUEST_CLIENT_ISOLATION_DISABLED": "Enable guest client isolation and verify it with a controlled connectivity test.",
        "GUEST_FIREWALL_ISOLATION_DISABLED": "Block guest-to-internal network access at the firewall and test the boundary.",
        "GUEST_OPEN_WITHOUT_CAPTIVE_PORTAL": "Protect open guest access with an approved captive portal and isolated network path.",
        "IOT_VLAN_EVIDENCE_MISSING": "Place IoT devices in a dedicated VLAN with explicit allow-list access to required services.",
        "IOT_CLIENT_ISOLATION_DISABLED": "Enable IoT client isolation where peer communication is not required.",
        "IOT_FIREWALL_ISOLATION_DISABLED": "Restrict IoT-to-internal traffic to documented service dependencies.",
        "MANAGEMENT_ACCESS_EXPOSED": "Restrict management WLAN access to managed administrator devices and approved identity groups.",
        "WPS_ENABLED": "Disable WPS on managed access points.",
    }
    recommendations = []
    seen_recommendations = set()
    for item in findings:
        recommendation = recommendation_by_code.get(item["code"])
        if recommendation and recommendation not in seen_recommendations:
            recommendations.append(recommendation)
            seen_recommendations.add(recommendation)

    return {
        "feature": "F194",
        "status": "empty" if not profiles else ("partial" if gap_count else "audited"),
        "summary": {
            "profile_count": len(profile_results),
            "enabled_profile_count": enabled_count,
            "disabled_profile_count": status_counts["disabled"],
            "corporate_profile_count": sum(1 for item in profile_results if item["purpose"] == "corporate" and item["enabled"] is not False),
            "guest_profile_count": sum(1 for item in profile_results if item["purpose"] == "guest" and item["enabled"] is not False),
            "iot_profile_count": sum(1 for item in profile_results if item["purpose"] == "iot" and item["enabled"] is not False),
            "management_profile_count": sum(1 for item in profile_results if item["purpose"] == "management" and item["enabled"] is not False),
            "compliant_profile_count": status_counts["compliant"],
            "non_compliant_profile_count": status_counts["non_compliant"],
            "evidence_incomplete_profile_count": status_counts["evidence_incomplete"],
            "profiles_with_findings": sum(1 for item in profile_results if item["finding_count"]),
            "finding_count": len(findings),
            "violation_count": violation_count,
            "evidence_gap_count": gap_count,
            "findings_by_severity": {key: severity_counts.get(key, 0) for key in SEVERITIES},
            "compliance_pct": compliance_pct,
            "observed_risk_score": observed_risk,
        },
        "profiles": sorted(profile_results, key=lambda item: (item["site_id"], item["profile_id"])),
        "findings": sorted(
            findings,
            key=lambda item: (
                SEVERITIES.index(item["severity"]),
                item["site_id"],
                item["profile_id"],
                item["code"],
            ),
        ),
        "recommendations": recommendations[:32],
        "note": (
            "This audit evaluates caller-supplied configuration evidence only. It does not prove effective live "
            "access-point, RADIUS or firewall state. Verify remediation on the managed devices. Secret values, "
            "SSID names and RADIUS server addresses are never returned."
        ),
    }


FEATURE = {
    "id": "F194",
    "slug": "enterprise_wlan_security_audit",
    "name": "Enterprise WLAN security posture audit",
    "category": "Security",
    "description": (
        "Audit office, guest, IoT and management WLAN profiles for 802.1X/EAP policy, RADIUS redundancy, "
        "certificate validation, PMF, WPS and network segmentation. Distinguishes confirmed violations "
        "from missing configuration evidence and never returns credentials or RADIUS addresses."
    ),
    "parameters": {
        "profiles": "up to 1024 normalized WLAN profile records with purpose, security mode, EAP, PMF, RADIUS and segmentation evidence",
        "policy": "optional policy overrides for minimum enterprise security, approved EAP methods, RADIUS redundancy and required controls",
    },
    "run": run,
}
