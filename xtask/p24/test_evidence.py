import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence import audit_release


DOWN = tuple(f"DOWN-{number:03}" for number in range(1, 8))
REL = tuple(f"REL-{number:03}" for number in range(1, 11))
R10 = tuple(f"R10-{number:03}" for number in range(1, 10))
CASE_IDS = DOWN + REL + R10
PUBLIC = (
    "rivetlua-core",
    "rivetlua-compiler",
    "rivetlua-runtime",
    "rivetlua-native",
    "rivetlua",
    "rivetlua-cli",
    "rivetlua-capi",
)
INPUT_HASH = "a" * 64
REQUIRED_SCOPES = {
    "DOWN-007": {
        "artifact_identity",
        "public_consumer",
        "runtime_only_audit",
        "crossbuild",
        "host_semantics",
    },
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
WAIVER_SUBCONDITIONS = {
    "PLAT-003": "cortex_m_board_physical_flash_boot_and_runtime_execution",
    "PLAT-004": "cortex_m_board_physical_resource_and_abort_measurements",
    "DOWN-007": "cortex_m_board_physical_startup_execution_and_measurement",
    "REL-007": "cortex_m_board_physical_success_and_measurement_evidence",
    "R10-006": "cortex_m_board_real_hardware_evidence",
    "R10-007": "DOWN-007_cortex_m_physical_board_execution",
}
PHYSICAL_CASES = ("DOWN-007", "REL-007", "R10-006", "R10-007")


def expected_inputs():
    return {
        case: {
            scope: INPUT_HASH
            for scope in REQUIRED_SCOPES.get(case, {"synthetic_report"})
        }
        for case in CASE_IDS
    }


def identity_evidence():
    producer_sources = {
        field: f"public-ref/identity/{field}"
        for field in (
            "crate_semver",
            "profile",
            "numeric",
            "bytecode",
            "c_abi",
            "native_artifact",
            "platform",
        )
    }
    return {
        "upgrade_strategy_source": "public-ref/identity/upgrade-strategy",
        "identities": [
            {
                "crate_semver": "1.0.0",
                "lua_profile": profile,
                "numeric_config": "i64f64",
                "bytecode_format_version": 17,
                "bytecode_authority": "P05 VerifiedModule",
                "c_abi_version": "c-abi-v3",
                "native_artifact_version": "native-v5",
                "platform_version": "platform-v8",
                "producer_sources": producer_sources.copy(),
            }
            for profile in ("lua54", "lua55")
        ],
    }


def waiver_document():
    return {
        "schema_version": 1,
        "record_count": 6,
        "allowed_case_ids": list(WAIVER_SUBCONDITIONS),
        "policy": {
            "reason": "user-authorized",
            "status": "USER_WAIVED",
            "counts_as_test_pass": False,
            "counts_as_hardware_evidence": False,
            "forbidden_deployment_status": "Supported",
            "deployment_status_without_board_evidence": [
                "BuildOnly",
                "Experimental",
            ],
        },
        "waivers": [
            {
                "case_id": case,
                "subcondition": subcondition,
                "reason": "user-authorized",
                "status": "USER_WAIVED",
                "requirements_not_waived": ["synthetic software evidence remains required"],
            }
            for case, subcondition in WAIVER_SUBCONDITIONS.items()
        ],
    }


def synthetic_evidence():
    expected = expected_inputs()
    cases = {
        case: {
            "status": "PASS",
            "inputs": dict(expected[case]),
            "matched": 1,
            "passed": 1,
            "failed": 0,
            "report_sha256": INPUT_HASH,
            "source": "p24-stage/synthetic-unit-report",
            "unresolved_high_risk": 0,
        }
        for case in CASE_IDS
    }
    for case in PHYSICAL_CASES:
        cases[case]["deployment_status"] = "BuildOnly"
    cases["R10-008"].update(identity_evidence())
    rights = {
        "package_names": {
            name: {
                "registry_name": name,
                "owner_source": f"public-ref/registry-owner/{name}",
                "publish_rights_source": f"public-ref/publish-rights/{name}",
            }
            for name in PUBLIC
        },
        "third_party_license_source": "public-ref/third-party-license",
        "notice_source": "public-ref/third-party-notice",
        "security_contact_source": "public-ref/security-contact",
    }
    return {"version": 1, "cases": cases, "rights": rights}, expected


class ReleaseEvidenceFixtures(unittest.TestCase):
    def assert_blocked(self, result, case, code):
        self.assertFalse(result["ready"])
        self.assertEqual(result["items"][case]["status"], "BLOCKED")
        self.assertEqual(result["items"][case]["code"], code)
        self.assertIn(case, result["blockers"])

    def test_synthetic_complete_inventory_has_exactly_26_cases(self):
        evidence, expected = synthetic_evidence()
        result = audit_release(evidence, expected, waiver_document())

        self.assertEqual(len(CASE_IDS), 26)
        self.assertEqual(set(result["items"]), set(CASE_IDS))
        self.assertTrue(result["ready"])
        self.assertEqual(result["blockers"], [])
        for case in PHYSICAL_CASES:
            self.assertEqual(result["items"][case]["status"], "PASS")
            self.assertEqual(result["items"][case]["physical"], "USER_WAIVED")

    def test_boolean_version_is_not_the_integer_schema_version(self):
        evidence, expected = synthetic_evidence()
        evidence["version"] = True

        result = audit_release(evidence, expected, waiver_document())

        self.assertFalse(result["ready"])
        self.assertEqual(len(result["items"]), 26)
        self.assertEqual(len(result["blockers"]), 26)
        for case in CASE_IDS:
            self.assertEqual(result["items"][case]["status"], "BLOCKED")
            self.assertEqual(result["items"][case]["code"], "E_EVIDENCE_VERSION")

    def test_missing_stale_empty_and_nonpass_evidence_blocks(self):
        evidence, expected = synthetic_evidence()
        missing = copy.deepcopy(evidence)
        del missing["cases"]["DOWN-003"]
        result = audit_release(missing, expected, waiver_document())
        self.assert_blocked(result, "DOWN-003", "E_EVIDENCE_MISSING")

        stale = copy.deepcopy(evidence)
        stale["cases"]["R10-008"]["inputs"]["typed_identity"] = "b" * 64
        result = audit_release(stale, expected, waiver_document())
        self.assert_blocked(result, "R10-008", "E_EVIDENCE_STALE")

        zero_match = copy.deepcopy(evidence)
        zero_match["cases"]["REL-008"]["matched"] = 0
        result = audit_release(zero_match, expected, waiver_document())
        self.assert_blocked(result, "REL-008", "E_EVIDENCE_COUNT")

        nonpass = copy.deepcopy(evidence)
        nonpass["cases"]["R10-005"]["status"] = "NOT_RUN"
        result = audit_release(nonpass, expected, waiver_document())
        self.assert_blocked(result, "R10-005", "E_EVIDENCE_STATUS")

    def test_unresolved_high_risk_blocks_the_security_release_criterion(self):
        evidence, expected = synthetic_evidence()
        evidence["cases"]["DOWN-004"]["unresolved_high_risk"] = 1

        result = audit_release(evidence, expected, waiver_document())

        self.assert_blocked(result, "R10-004", "E_HIGH_RISK")

    def test_stage_registry_sources_cannot_substitute_for_formal_publish_rights(self):
        evidence, expected = synthetic_evidence()
        evidence["rights"]["package_names"]["rivetlua-core"]["publish_rights_source"] = (
            "p24-stage/synthetic-owner-record"
        )

        result = audit_release(evidence, expected, waiver_document())

        self.assert_blocked(result, "REL-010", "E_PUBLISH_RIGHTS")
        self.assertEqual(result["items"]["R10-009"]["code"], "E_PRODUCER_BLOCKED")

    def test_release_identity_keeps_semver_profiles_bytecode_and_abi_evidence_separate(self):
        evidence, expected = synthetic_evidence()
        result = audit_release(evidence, expected, waiver_document())
        self.assertEqual(result["items"]["R10-008"]["status"], "PASS")
        self.assertEqual(
            {item["lua_profile"] for item in evidence["cases"]["R10-008"]["identities"]},
            {"lua54", "lua55"},
        )

        zero_x = copy.deepcopy(evidence)
        for item in zero_x["cases"]["R10-008"]["identities"]:
            item["crate_semver"] = "0.0.0"
        result = audit_release(zero_x, expected, waiver_document())
        self.assert_blocked(result, "R10-008", "E_RELEASE_IDENTITY")

        changes = (
            ("duplicate Lua profile", lambda items: items[1].update(lua_profile="lua54")),
            ("bytecode format drift", lambda items: items[0].update(bytecode_format_version=18)),
        )
        for label, change in changes:
            with self.subTest(identity_error=label):
                invalid = copy.deepcopy(evidence)
                change(invalid["cases"]["R10-008"]["identities"])
                result = audit_release(invalid, expected, waiver_document())
                self.assert_blocked(result, "R10-008", "E_RELEASE_IDENTITY")

        for source in (
            "crate_semver",
            "profile",
            "numeric",
            "bytecode",
            "c_abi",
            "native_artifact",
            "platform",
        ):
            with self.subTest(missing_identity_source=source):
                invalid = copy.deepcopy(evidence)
                invalid["cases"]["R10-008"]["identities"][0]["producer_sources"].pop(source)
                result = audit_release(invalid, expected, waiver_document())
                self.assert_blocked(result, "R10-008", "E_RELEASE_IDENTITY")

        for version in ("c_abi_version", "native_artifact_version", "platform_version"):
            with self.subTest(missing_identity_version=version):
                invalid = copy.deepcopy(evidence)
                invalid["cases"]["R10-008"]["identities"][0][version] = ""
                result = audit_release(invalid, expected, waiver_document())
                self.assert_blocked(result, "R10-008", "E_RELEASE_IDENTITY")

    def test_physical_waivers_do_not_replace_software_evidence(self):
        evidence, expected = synthetic_evidence()
        for case in PHYSICAL_CASES:
            with self.subTest(waived_case=case):
                missing_software = copy.deepcopy(evidence)
                missing_software["cases"][case]["status"] = "NOT_RUN"
                result = audit_release(
                    missing_software, expected, waiver_document()
                )
                self.assert_blocked(result, case, "E_EVIDENCE_STATUS")
                self.assertNotIn("physical", result["items"][case])

        unsupported = copy.deepcopy(evidence)
        unsupported["cases"]["DOWN-007"]["deployment_status"] = "Supported"
        result = audit_release(unsupported, expected, waiver_document())
        self.assert_blocked(result, "DOWN-007", "E_PHYSICAL_WAIVER")

    def test_invalid_downstream_waiver_blocks_its_release_dependent(self):
        evidence, expected = synthetic_evidence()
        evidence["cases"]["DOWN-007"]["deployment_status"] = "Supported"
        evidence["cases"]["REL-007"]["deployment_status"] = "BuildOnly"
        self.assertEqual(evidence["cases"]["DOWN-007"]["status"], "PASS")
        self.assertEqual(evidence["cases"]["REL-007"]["status"], "PASS")

        result = audit_release(evidence, expected, waiver_document())

        self.assert_blocked(result, "DOWN-007", "E_PHYSICAL_WAIVER")
        self.assert_blocked(result, "REL-007", "E_PRODUCER_BLOCKED")
        self.assertNotIn("physical", result["items"]["REL-007"])


if __name__ == "__main__":
    unittest.main()
