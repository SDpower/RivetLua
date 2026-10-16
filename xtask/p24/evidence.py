"""P24 發布證據的只讀、逐案例相關輸入審核；不執行驗收或發布。"""

from __future__ import annotations

import re

PUBLIC = frozenset({
    "rivetlua-core", "rivetlua-compiler", "rivetlua-runtime", "rivetlua-native",
    "rivetlua", "rivetlua-cli", "rivetlua-capi",
})
DOWN = tuple(f"DOWN-{number:03}" for number in range(1, 8))
REL = tuple(f"REL-{number:03}" for number in range(1, 11))
R10 = tuple(f"R10-{number:03}" for number in range(1, 10))
CASE_IDS = DOWN + REL + R10
WAIVED = {
    "DOWN-007": "cortex_m_board_physical_startup_execution_and_measurement",
    "REL-007": "cortex_m_board_physical_success_and_measurement_evidence",
    "R10-006": "cortex_m_board_real_hardware_evidence",
    "R10-007": "DOWN-007_cortex_m_physical_board_execution",
}
WAIVER_SUBCONDITIONS = {
    "PLAT-003": "cortex_m_board_physical_flash_boot_and_runtime_execution",
    "PLAT-004": "cortex_m_board_physical_resource_and_abort_measurements",
    **WAIVED,
}
REQUIRED_SCOPES = {
    "DOWN-007": {"artifact_identity", "public_consumer", "runtime_only_audit", "crossbuild", "host_semantics"},
    "REL-007": {"package_registry", "downstream", "license_notice"},
    "REL-008": {"package_negative"},
    "REL-009": {"consumer_negative"},
    "REL-010": {"registry_rights", "license_notice"},
    "R10-001": {"sdk_clean_consumer"},
    "R10-002": {"p15_profile", "p17_profile"},
    "R10-003": {"p18_package_matrix"},
    "R10-004": {"security_findings", "sandbox_escape"},
    "R10-005": {"p22_policy_defaults"},
    "R10-006": {"runtime_only", "aot_loader", "cross_target", "security"},
    "R10-007": {"public_consumers", "artifact_identity", "host_semantics"},
    "R10-008": {"typed_identity", "upgrade_strategy"},
    "R10-009": {"registry_rights"},
}


def _hash(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _source(value: object) -> bool:
    return (isinstance(value, str) and len(value) <= 256
            and re.fullmatch(r"[A-Za-z0-9._:/#@+-]+", value) is not None
            and not value.startswith(("/", "~")) and ".." not in value)


def _formal_source(value: object) -> bool:
    return _source(value) and "p24-stage" not in value.lower()


def _record(case: str, record: object, expected: object) -> str | None:
    if not isinstance(expected, dict) or not expected or any(not isinstance(k, str) or not _hash(v)
                                                             for k, v in expected.items()):
        return "E_RELEVANT_INPUTS"
    if not REQUIRED_SCOPES.get(case, set()) <= set(expected):
        return "E_RELEVANT_INPUTS"
    if not isinstance(record, dict):
        return "E_EVIDENCE_MISSING"
    if record.get("status") != "PASS":
        return "E_EVIDENCE_STATUS"
    actual = record.get("inputs")
    if not isinstance(actual, dict) or any(actual.get(key) != digest for key, digest in expected.items()):
        return "E_EVIDENCE_STALE"
    matched, passed, failed = (record.get(key) for key in ("matched", "passed", "failed"))
    if any(type(value) is not int for value in (matched, passed, failed)) or matched <= 0 or passed != matched or failed != 0:
        return "E_EVIDENCE_COUNT"
    if not _hash(record.get("report_sha256")) or not _source(record.get("source")):
        return "E_EVIDENCE_PROVENANCE"
    risk = record.get("unresolved_high_risk")
    if type(risk) is not int or risk != 0:
        return "E_HIGH_RISK"
    return None


def _rights(value: object) -> bool:
    if not isinstance(value, dict) or not all(_formal_source(value.get(key)) for key in (
        "third_party_license_source", "notice_source", "security_contact_source"
    )):
        return False
    names = value.get("package_names")
    if not isinstance(names, dict) or set(names) != PUBLIC:
        return False
    for name, item in names.items():
        if not isinstance(item, dict) or item.get("registry_name") != name:
            return False
        if not _formal_source(item.get("owner_source")) or not _formal_source(item.get("publish_rights_source")):
            return False
    return True


def _identity(value: object) -> bool:
    if not isinstance(value, dict) or not _source(value.get("upgrade_strategy_source")):
        return False
    identities = value.get("identities")
    if not isinstance(identities, list) or len(identities) != 2:
        return False
    profiles, versions, formats = set(), set(), set()
    for identity in identities:
        if not isinstance(identity, dict) or identity.get("lua_profile") not in ("lua54", "lua55"):
            return False
        profiles.add(identity["lua_profile"])
        version = identity.get("crate_semver")
        if not isinstance(version, str) or re.fullmatch(r"[1-9][0-9]*\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version) is None:
            return False
        versions.add(version)
        if (identity.get("numeric_config") != "i64f64" or identity.get("bytecode_authority") != "P05 VerifiedModule"
                or type(identity.get("bytecode_format_version")) is not int or identity["bytecode_format_version"] <= 0):
            return False
        formats.add(identity["bytecode_format_version"])
        if not all(_source(identity.get(key)) for key in (
            "c_abi_version", "native_artifact_version", "platform_version"
        )):
            return False
        producers = identity.get("producer_sources")
        if not isinstance(producers, dict) or not all(_source(producers.get(key)) for key in (
            "crate_semver", "profile", "numeric", "bytecode", "c_abi", "native_artifact", "platform"
        )):
            return False
    return profiles == {"lua54", "lua55"} and len(versions) == 1 and len(formats) == 1


def _waivers(value: object) -> bool:
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1 or type(value.get("record_count")) is not int
            or value["record_count"] != 6):
        return False
    allowed = value.get("allowed_case_ids")
    if not isinstance(allowed, list) or len(allowed) != 6 or any(not isinstance(case, str) for case in allowed):
        return False
    if set(allowed) != set(WAIVER_SUBCONDITIONS):
        return False
    policy = value.get("policy")
    deployments = policy.get("deployment_status_without_board_evidence") if isinstance(policy, dict) else None
    if (not isinstance(policy, dict) or policy.get("reason") != "user-authorized"
            or policy.get("status") != "USER_WAIVED"
            or policy.get("counts_as_test_pass") is not False
            or policy.get("counts_as_hardware_evidence") is not False
            or policy.get("forbidden_deployment_status") != "Supported"
            or not isinstance(deployments, list) or any(not isinstance(status, str) for status in deployments)
            or set(deployments) != {"BuildOnly", "Experimental"}):
        return False
    records = value.get("waivers")
    if not isinstance(records, list) or len(records) != 6:
        return False
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            return False
        case = record.get("case_id")
        if (not isinstance(case, str) or case in seen or case not in WAIVER_SUBCONDITIONS
                or record.get("subcondition") != WAIVER_SUBCONDITIONS[case]
                or record.get("status") != "USER_WAIVED" or record.get("reason") != "user-authorized"
                or not isinstance(record.get("requirements_not_waived"), list)
                or not record["requirements_not_waived"]):
            return False
        seen.add(case)
    return seen == set(WAIVER_SUBCONDITIONS)


def audit_release(evidence: dict, expected_inputs: dict, waiver_doc: dict) -> dict:
    """只核 supplied 證據的一致性；輸出不包含來源內容或權杖。"""
    valid_root = (isinstance(evidence, dict) and type(evidence.get("version")) is int
                  and evidence["version"] == 1 and isinstance(evidence.get("cases"), dict))
    cases = evidence["cases"] if valid_root else {}
    expected_inputs = expected_inputs if isinstance(expected_inputs, dict) else {}
    items = {}
    for case in CASE_IDS:
        code = _record(case, cases.get(case), expected_inputs.get(case)) if valid_root else "E_EVIDENCE_VERSION"
        items[case] = {"status": "BLOCKED" if code else "PASS", "code": code or "E_OK"}

    if items["REL-010"]["status"] == "PASS" and not _rights(evidence.get("rights")):
        items["REL-010"] = {"status": "BLOCKED", "code": "E_PUBLISH_RIGHTS"}
    if items["R10-008"]["status"] == "PASS" and not _identity(cases["R10-008"]):
        items["R10-008"] = {"status": "BLOCKED", "code": "E_RELEASE_IDENTITY"}
    if items["R10-004"]["status"] == "PASS" and any(
        isinstance(record, dict) and type(record.get("unresolved_high_risk")) is int
        and record["unresolved_high_risk"] > 0 for record in cases.values()
    ):
        items["R10-004"] = {"status": "BLOCKED", "code": "E_HIGH_RISK"}

    waiver_ok = _waivers(waiver_doc)
    for case in WAIVED:
        if items[case]["status"] != "PASS":
            continue
        deployment = cases[case].get("deployment_status")
        if not waiver_ok or deployment not in ("BuildOnly", "Experimental"):
            items[case] = {"status": "BLOCKED", "code": "E_PHYSICAL_WAIVER"}
        else:
            items[case]["physical"] = "USER_WAIVED"

    for number in range(1, 8):
        dependency = f"DOWN-{number:03}"
        release = f"REL-{number:03}"
        if items[release]["status"] == "PASS" and items[dependency]["status"] != "PASS":
            items[release] = {"status": "BLOCKED", "code": "E_PRODUCER_BLOCKED"}

    dependencies = {
        "R10-001": ("DOWN-001", "REL-001"),
        "R10-006": ("DOWN-007", "REL-007"),
        "R10-007": DOWN + REL[:7],
        "R10-009": ("REL-010",),
    }
    for case, required in dependencies.items():
        if items[case]["status"] == "PASS" and any(items[producer]["status"] != "PASS" for producer in required):
            items[case] = {"status": "BLOCKED", "code": "E_PRODUCER_BLOCKED"}
    blockers = [case for case in CASE_IDS if items[case]["status"] != "PASS"]
    return {"version": 1, "ready": not blockers, "items": items, "blockers": blockers}
