import json

import pytest
from pydantic import ValidationError

from scopeweaver.modules.active_directory import ADExport, audit_export
from scopeweaver.modules.passwords import (
    PasswordDataset,
    PasswordPolicy,
    assess_sample,
    audit_dataset,
    audit_policy,
    synthetic_lab,
)


@pytest.mark.parametrize(
    "value,pattern",
    [
        ("P@ssw0rd2026!", "common_dictionary_fragment_or_substitution"),
        ("1234567890", "keyboard_or_numeric_sequence"),
        ("abcabcabcabc", "repeated_character_or_block"),
        ("Summer2026!", "season_pattern"),
        ("SomeCompany-secret", "context_specific_word"),
    ],
)
def test_patterns_are_detected_without_guessing(value, pattern):
    result = assess_sample(value, ["company"], 15)
    assert pattern in result["patterns"]
    assert "crack" not in {k for k in result if k != "limitations"}


def test_password_lab_keeps_values_and_hashes_out_of_results():
    dataset = synthetic_lab()
    result = audit_dataset(dataset)
    serialized = result.model_dump_json()
    for sample in dataset.samples:
        assert sample.value.get_secret_value() not in serialized
    assert result.observations["synthetic"]
    assert len(result.observations["samples"]) == len(dataset.samples)
    assert result.observations["samples"][-1]["heuristic_score"] == 4


def test_mfa_context_changes_length_baseline():
    single = audit_policy(PasswordPolicy(minimum_length=8, mfa_required=False), "p")
    mfa = audit_policy(PasswordPolicy(minimum_length=8, mfa_required=True), "p")
    unknown = audit_policy(PasswordPolicy(minimum_length=8), "p")
    assert len(single) == 1 and single[0].severity.value == "Medium"
    assert mfa == []
    assert unknown[0].severity.value == "Info"
    assert audit_policy(PasswordPolicy(), "p") == []


def test_all_policy_rules_and_unknown_fields():
    policy = PasswordPolicy(
        minimum_length=6,
        maximum_length=32,
        blocklist_enabled=False,
        rate_limit_enabled=False,
        composition_required=True,
        periodic_rotation_required=True,
        reversible_encryption=True,
        lockout_threshold=0,
        mfa_required=False,
    )
    assert len(audit_policy(policy, "p")) == 8
    with pytest.raises(ValidationError):
        PasswordPolicy(minimum_length=20, maximum_length=10)
    data = synthetic_lab().model_dump(mode="json")
    data["synthetic"] = False
    with pytest.raises(ValidationError):
        PasswordDataset.model_validate(data)
    data["synthetic"] = True
    data["samples"][1]["id"] = data["samples"][0]["id"]
    with pytest.raises(ValidationError, match="unique"):
        PasswordDataset.model_validate(data)


def export_data():
    return {
        "domain": "lab.test",
        "policy": {"minimum_length": 15, "mfa_required": False},
        "accounts": [
            {
                "id": "u1",
                "name": "svc-web",
                "kind": "service",
                "enabled": True,
                "user_account_control": 0x400000 | 0x80000 | 0x20 | 0x1000000,
                "encryption_types": 4,
                "spns": ["HTTP/app.lab.test"],
                "allowed_to_delegate_to": ["cifs/files.lab.test"],
                "rbcd_principals": ["u2"],
            },
            {"id": "u2", "name": "disabled", "enabled": False, "user_account_control": 0x400000},
            {
                "id": "dc1",
                "name": "dc",
                "kind": "domain_controller",
                "enabled": True,
                "user_account_control": 0x80000 | 0x2000,
                "encryption_types": 24,
            },
            {
                "id": "u3",
                "name": "legacy",
                "enabled": True,
                "user_account_control": 0x200000,
                "encryption_types": 3,
                "admin_count": 1,
            },
        ],
        "groups": [
            {"id": "g1", "name": "Domain Admins", "privileged": True, "members": ["g2"]},
            {"id": "g2", "name": "Nested", "privileged": False, "members": ["u1", "g1"]},
        ],
        "permissions": [
            {
                "principal": "S-1-5-11",
                "target": "g1",
                "rights": ["WriteDacl"],
                "access_type": "Allow",
                "privileged_target": True,
            },
            {
                "principal": "S-1-5-11",
                "target": "g1",
                "rights": ["GenericAll"],
                "access_type": "Deny",
                "privileged_target": True,
            },
        ],
    }


def test_ad_nested_groups_flags_delegation_and_permissions():
    result = audit_export(ADExport.model_validate(export_data()))
    titles = {f.title for f in result.findings}
    assert {
        "Kerberos pre-authentication is disabled",
        "Unconstrained delegation configured",
        "RC4 permitted without AES account support",
        "DES Kerberos encryption permitted",
        "Service account has privileged group membership",
        "Sensitive permission on privileged object",
        "Privileged account is not marked non-delegatable",
        "Delegation permits protocol transition",
        "Delegation relationships require review",
        "Password requirement flag is disabled",
        "adminCount requires protection review",
    } <= titles
    assert result.observations["transitive_privileged_members"]["g1"] == ["u1"]
    assert result.observations["revisited_group_nodes"]
    assert not any(f.target in {"u2", "dc1"} for f in result.findings)
    assert sum(f.title == "Sensitive permission on privileged object" for f in result.findings) == 1


def test_ad_unknown_is_not_assumed_secure_or_exploitable():
    data = export_data()
    data["groups"][0]["members"].append("missing-id")
    data["accounts"][0]["encryption_types"] = 0
    result = audit_export(ADExport.model_validate(data))
    assert result.status == "partial"
    assert result.observations["unresolved_members"] == ["missing-id"]
    assert "u1" in result.observations["unknown_encryption_accounts"]
    assert not any("RC4" in f.title and f.target == "u1" for f in result.findings)


def test_ad_rejects_unknown_schema_duplicate_ids_and_raw_secrets():
    for mutation in [
        lambda d: d.update(schema_version="2"),
        lambda d: d["accounts"].append(d["accounts"][0]),
        lambda d: d["accounts"][0].update(password="secret"),
    ]:
        data = export_data()
        mutation(data)
        with pytest.raises(ValidationError):
            ADExport.model_validate_json(json.dumps(data))
