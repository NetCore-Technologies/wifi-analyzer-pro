"""Evidence-bound, two-person RF change approval packet builder (F208)."""
from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from datetime import datetime, timedelta, timezone

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
ADAPTERS = {"openwrt", "unifi", "mikrotik"}
WIDTHS = {20, 40, 80, 160, 320}
MAX_RADIOS = 256


def _id(value, field):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a valid identifier")
    return value.strip()


def _timestamp(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _number(value, field, low, high):
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be finite")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not math.isfinite(result) or not low <= result <= high:
        raise ValueError(f"{field} is outside its supported range")
    return round(result, 3)


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    site_id = _id(payload.get("site_id"), "site_id")
    adapter_id = payload.get("adapter_id")
    if adapter_id not in ADAPTERS:
        raise ValueError(f"adapter_id must be one of {sorted(ADAPTERS)}")
    requester = _id(payload.get("requested_by"), "requested_by")
    created = _timestamp(payload.get("created_at"), "created_at")
    expires = _timestamp(payload.get("expires_at"), "expires_at")
    ttl = (expires - created).total_seconds()
    if not 60 <= ttl <= 86400:
        raise ValueError("expires_at must be between 1 minute and 24 hours after creation")
    if expires <= datetime.now(timezone.utc):
        raise ValueError("expires_at must be in the future")
    if payload.get("required_approvals", 2) != 2 or isinstance(payload.get("required_approvals", 2), bool):
        raise ValueError("required_approvals must be exactly 2")

    dataset = payload.get("dataset")
    if not isinstance(dataset, dict):
        raise ValueError("dataset must be retained regulatory dataset metadata")
    try:
        dataset_ref = str(uuid.UUID(dataset.get("dataset_ref")))
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError("dataset.dataset_ref must be a valid UUID") from error
    fingerprint = dataset.get("fingerprint_sha256")
    if not isinstance(fingerprint, str) or not SHA256.fullmatch(fingerprint):
        raise ValueError("dataset.fingerprint_sha256 must be a lowercase SHA-256 digest")
    jurisdiction = dataset.get("jurisdiction")
    if not isinstance(jurisdiction, str) or not re.fullmatch(r"(?:[A-Z]{2}|EU)", jurisdiction):
        raise ValueError("dataset.jurisdiction must be an ISO alpha-2 jurisdiction or EU")
    dataset_id = _id(dataset.get("dataset_id"), "dataset.dataset_id")
    version = dataset.get("version")
    if not isinstance(version, str) or not version.strip() or len(version) > 64:
        raise ValueError("dataset.version must contain 1 to 64 characters")
    reviewer = _id(dataset.get("reviewer_id"), "dataset.reviewer_id")
    review_reference = dataset.get("review_reference")
    if not isinstance(review_reference, str) or not review_reference.strip() or len(review_reference) > 256:
        raise ValueError("dataset.review_reference must contain 1 to 256 characters")
    reviewed_at = _timestamp(dataset.get("reviewed_at"), "dataset.reviewed_at")
    if reviewed_at > created + timedelta(minutes=5):
        raise ValueError("dataset.reviewed_at cannot be after request creation")

    plan = payload.get("plan")
    if not isinstance(plan, dict) or plan.get("site_id") != site_id:
        raise ValueError("plan must be an F207 result for the requested site")
    if plan.get("status") != "eligible":
        raise ValueError("only a fully eligible F207 plan can enter change approval")
    app = plan.get("change_application")
    if not isinstance(app, dict) or app.get("applied") is not False or app.get("execution_method") != "preview_only":
        raise ValueError("plan must be a non-applied F207 preview")
    plan_dataset = plan.get("dataset")
    if not isinstance(plan_dataset, dict) or plan_dataset.get("fingerprint_sha256") != fingerprint:
        raise ValueError("plan regulatory fingerprint does not match the retained dataset")

    source_radios = payload.get("radios")
    planned_radios = plan.get("radios")
    if not isinstance(source_radios, list) or not 1 <= len(source_radios) <= MAX_RADIOS:
        raise ValueError(f"radios must contain 1 to {MAX_RADIOS} records")
    if not isinstance(planned_radios, list) or len(planned_radios) != len(source_radios):
        raise ValueError("plan radio count must match the source capability snapshot")
    if plan.get("radio_count") != len(source_radios) or plan.get("eligible_radio_count") != len(source_radios):
        raise ValueError("plan radio counters must confirm every source radio is eligible")

    sources = {}
    for index, radio in enumerate(source_radios):
        if not isinstance(radio, dict):
            raise ValueError(f"radios[{index}] must be an object")
        radio_id = _id(radio.get("radio_id"), f"radios[{index}].radio_id")
        if radio_id in sources:
            raise ValueError("radio_id values must be unique")
        if radio.get("site_id") != site_id or radio.get("jurisdiction") != jurisdiction:
            raise ValueError(f"radios[{index}] site and jurisdiction must match the reviewed dataset")
        sources[radio_id] = radio

    changes = []
    seen = set()
    for index, item in enumerate(planned_radios):
        if not isinstance(item, dict):
            raise ValueError(f"plan.radios[{index}] must be an object")
        radio_id = _id(item.get("radio_id"), f"plan.radios[{index}].radio_id")
        if radio_id in seen or radio_id not in sources:
            raise ValueError("plan must contain exactly one result per source radio")
        seen.add(radio_id)
        if item.get("status") != "eligible":
            raise ValueError(f"radio {radio_id} is not eligible for change approval")
        config = item.get("recommended_configuration")
        if not isinstance(config, dict):
            raise ValueError(f"radio {radio_id} is missing its recommended configuration")
        if config.get("change_required") is not True:
            continue
        source = sources[radio_id]
        before_channel = source.get("current_channel")
        before_width = source.get("current_channel_width_mhz")
        after_channel = config.get("channel")
        after_width = config.get("channel_width_mhz")
        if isinstance(after_channel, bool) or not isinstance(after_channel, int) or not 1 <= after_channel <= 233:
            raise ValueError(f"radio {radio_id} recommended channel is invalid")
        if isinstance(after_width, bool) or not isinstance(after_width, int) or after_width not in WIDTHS:
            raise ValueError(f"radio {radio_id} recommended channel width is invalid")
        if before_channel is not None and (isinstance(before_channel, bool) or not isinstance(before_channel, int) or not 1 <= before_channel <= 233):
            raise ValueError(f"radio {radio_id} current channel is invalid")
        if before_width is not None and (isinstance(before_width, bool) or not isinstance(before_width, int) or before_width not in WIDTHS):
            raise ValueError(f"radio {radio_id} current channel width is invalid")
        if before_channel == after_channel and before_width == after_width and config.get("proposed_eirp_dbm") in (None, source.get("current_eirp_dbm")):
            raise ValueError(f"radio {radio_id} is marked change_required without a material change")
        observed = _timestamp(source.get("capabilities_observed_at"), f"radios[{index}].capabilities_observed_at")
        refs = config.get("source_references", [])
        if not isinstance(refs, list) or len(refs) > 20 or any(not isinstance(ref, dict) for ref in refs):
            raise ValueError(f"radio {radio_id} source references are invalid")
        changes.append({
            "radio_id": radio_id,
            "ap_id": _id(source.get("ap_id"), f"radios[{index}].ap_id"),
            "band": source.get("band"),
            "capability_source": source.get("capability_source"),
            "capabilities_observed_at": observed.isoformat(timespec="seconds"),
            "installation_reference": _id(source.get("installation_reference"), f"radios[{index}].installation_reference"),
            "before": {
                "channel": before_channel,
                "channel_width_mhz": before_width,
                "eirp_dbm": _number(source.get("current_eirp_dbm"), f"radios[{index}].current_eirp_dbm", -20, 60),
            },
            "after": {
                "channel": after_channel,
                "channel_width_mhz": after_width,
                "eirp_dbm": _number(config.get("proposed_eirp_dbm"), f"plan.radios[{index}].proposed_eirp_dbm", -20, 60),
            },
            "rule_id": _id(config.get("rule_id"), f"plan.radios[{index}].rule_id"),
            "source_references": refs,
            "dfs_required": config.get("dfs_required") is True,
            "requires_dfs_cac_before_activation": config.get("requires_dfs_cac_before_activation") is True,
            "afc_required": config.get("afc_required") is True,
            "eirp_ceiling_dbm": _number(config.get("eirp_ceiling_dbm"), f"plan.radios[{index}].eirp_ceiling_dbm", -20, 60),
        })
    if seen != set(sources):
        raise ValueError("plan radios do not match the source capability snapshot")
    if not changes:
        raise ValueError("the F207 plan contains no radio configuration changes to approve")
    changes.sort(key=lambda item: item["radio_id"])
    packet = {
        "schema_version": 1,
        "workflow": "two_person_rf_change_approval",
        "site_id": site_id,
        "adapter_id": adapter_id,
        "requested_by": requester,
        "created_at": created.isoformat(timespec="seconds"),
        "expires_at": expires.isoformat(timespec="seconds"),
        "required_approvals": 2,
        "dataset": {
            "dataset_ref": dataset_ref,
            "fingerprint_sha256": fingerprint,
            "jurisdiction": jurisdiction,
            "dataset_id": dataset_id,
            "version": version.strip(),
            "reviewer_id": reviewer,
            "review_reference": review_reference.strip(),
            "reviewed_at": reviewed_at.isoformat(timespec="seconds"),
        },
        "plan": {
            "status": plan["status"],
            "radio_count": plan["radio_count"],
            "eligible_radio_count": plan["eligible_radio_count"],
            "rule_evaluation_count": plan.get("rule_evaluation_count"),
        },
        "change_count": len(changes),
        "changes": changes,
        "execution": {
            "status": "blocked_no_write_capable_adapter",
            "applied": False,
            "write_adapter_available": False,
            "note": "The registered controller adapters are read-only; approval records do not apply router configuration.",
        },
        "limitations": [
            "Capability observations and installation references are caller-declared snapshots, not signed live controller state.",
            "The retained regulatory dataset must remain unrevoked and effective at approval and deployment.",
            "Approval is not proof of legal compliance, DFS radar clearance, AFC grant validity at deployment or operational safety.",
            "Deployment remains disabled until an authenticated write-capable adapter with read-back verification and rollback is registered.",
        ],
    }
    encoded = json.dumps(packet, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return {
        "status": "approval_packet_created",
        "packet": packet,
        "packet_sha256": hashlib.sha256(encoded).hexdigest(),
        "required_approvals": 2,
        "execution_allowed": False,
    }


FEATURE = {
    "id": "F208",
    "slug": "rf_change_approval_packet",
    "name": "RF controller change approval packet",
    "category": "RF change management",
    "description": "Bind F207 radio recommendations to an immutable retained F206 dataset and exact controller capability snapshot; require two independent site managers before any future deployment, which remains blocked while adapters are read-only.",
    "parameters": {
        "site_id": "Site identifier owning the dataset and radios",
        "adapter_id": "Registered adapter: openwrt, unifi or mikrotik",
        "dataset": "Retained F206 dataset reference, fingerprint and review metadata",
        "plan": "Fully eligible, non-applied F207 result",
        "radios": "Exact source capability snapshots used for F207",
        "requested_by": "Authenticated requester username",
        "created_at": "Timezone-aware packet creation timestamp",
        "expires_at": "Timestamp 1 minute to 24 hours after creation",
        "required_approvals": "Exactly two distinct approvers other than requester",
    },
    "run": run,
}
