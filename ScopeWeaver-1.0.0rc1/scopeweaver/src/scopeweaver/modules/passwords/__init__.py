from __future__ import annotations

import re
import unicodedata
from typing import Literal

from pydantic import Field, SecretStr, model_validator

from scopeweaver.core.models import Finding, ModuleResult, Severity, StrictModel, finding

NIST_PASSWORDS = "https://pages.nist.gov/800-63-4/sp800-63b.html#passwords"
COMMON = {
    "password",
    "admin",
    "welcome",
    "qwerty",
    "letmein",
    "dragon",
    "monkey",
    "iloveyou",
    "changeme",
    "football",
    "secret",
    "пароль",
    "йцукен",
}


class PasswordPolicy(StrictModel):
    minimum_length: int | None = Field(default=None, ge=0, le=1024)
    maximum_length: int | None = Field(default=None, ge=1, le=10000)
    mfa_required: bool | None = None
    blocklist_enabled: bool | None = None
    rate_limit_enabled: bool | None = None
    composition_required: bool | None = None
    periodic_rotation_required: bool | None = None
    reversible_encryption: bool | None = None
    lockout_threshold: int | None = Field(default=None, ge=0, le=10000)

    @model_validator(mode="after")
    def coherent(self) -> PasswordPolicy:
        if (
            self.minimum_length is not None
            and self.maximum_length is not None
            and self.minimum_length > self.maximum_length
        ):
            raise ValueError("minimum_length exceeds maximum_length")
        return self


class Sample(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    value: SecretStr = Field(min_length=1, max_length=1024)


class PasswordDataset(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    synthetic: Literal[True]
    policy: PasswordPolicy
    samples: list[Sample] = Field(default_factory=list, max_length=10000)
    context_words: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def unique_ids(self) -> PasswordDataset:
        if len({s.id for s in self.samples}) != len(self.samples):
            raise ValueError("sample IDs must be unique")
        return self


def audit_policy(policy: PasswordPolicy, target: str, module: str = "passwords") -> list[Finding]:
    findings: list[Finding] = []

    def add(
        rule: str,
        title: str,
        severity: Severity,
        explanation: str,
        evidence: dict[str, object],
        remedy: str,
    ) -> None:
        findings.append(
            finding(
                module,
                target,
                rule,
                title,
                severity,
                explanation,
                evidence,
                remedy,
                "CWE-521",
                [NIST_PASSWORDS, "https://cwe.mitre.org/data/definitions/521.html"],
            )
        )

    # MFA status unknown: do not silently assume a single-factor deployment.
    threshold = 8 if policy.mfa_required else 15
    if policy.minimum_length is not None and policy.minimum_length < threshold:
        severity = Severity.MEDIUM if policy.mfa_required is not None else Severity.INFO
        add(
            "policy-length",
            "Password minimum length requires review",
            severity,
            "The configured minimum is below the selected NIST-aligned baseline. "
            "Unknown MFA status makes the 15-character comparison advisory.",
            {
                "minimum_length": policy.minimum_length,
                "mfa_required": policy.mfa_required,
                "comparison_minimum": threshold,
            },
            "Use at least 15 characters for single-factor passwords, or at least 8 when MFA is required.",
        )
    if policy.maximum_length is not None and policy.maximum_length < 64:
        add(
            "policy-maximum",
            "Long passphrases are restricted",
            Severity.LOW,
            "The policy prevents passwords of at least 64 characters.",
            {"maximum_length": policy.maximum_length},
            "Permit a maximum length of at least 64.",
        )
    if policy.blocklist_enabled is False:
        add(
            "policy-blocklist",
            "Password blocklist is disabled",
            Severity.MEDIUM,
            "The supplied policy does not reject common or compromised passwords.",
            {"blocklist_enabled": False},
            "Use a locally managed or approved compromised-password blocklist.",
        )
    if policy.rate_limit_enabled is False:
        add(
            "policy-rate",
            "Authentication rate limiting is disabled",
            Severity.MEDIUM,
            "The supplied policy has no rate-limiting control.",
            {"rate_limit_enabled": False},
            "Apply adaptive throttling and monitor failed authentication.",
        )
    if policy.reversible_encryption is True:
        add(
            "policy-reversible",
            "Reversible password storage is enabled",
            Severity.HIGH,
            "Reversible storage increases exposure of reusable secrets.",
            {"reversible_encryption": True},
            "Disable reversible storage and migrate dependent integrations.",
        )
    if policy.lockout_threshold == 0:
        add(
            "policy-lockout",
            "Account lockout is disabled",
            Severity.INFO,
            "A zero lockout threshold requires review of alternative throttling controls.",
            {"lockout_threshold": 0},
            "Validate adaptive throttling and a balanced account lockout policy.",
        )
    if policy.composition_required:
        add(
            "policy-composition",
            "Composition rules require usability review",
            Severity.INFO,
            "Character-class requirements can encourage predictable substitutions.",
            {"composition_required": True},
            "Prefer length, blocklists and MFA over composition rules alone.",
        )
    if policy.periodic_rotation_required:
        add(
            "policy-rotation",
            "Periodic password rotation requires review",
            Severity.INFO,
            "Routine forced changes may encourage predictable variations.",
            {"periodic_rotation_required": True},
            "Require changes on evidence of compromise and assess any sector-specific obligations.",
        )
    return findings


def assess_sample(value: str, context: list[str], minimum: int) -> dict[str, object]:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    patterns: list[str] = []
    if len(value) < minimum:
        patterns.append("below_policy_length")
    if value.isdecimal():
        patterns.append("digits_only")
    if re.search(r"(.{1,8})\1{2,}", normalized):
        patterns.append("repeated_character_or_block")
    rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "йцукенгшщзхъ"]
    if any(
        row[i : i + 4] in normalized or row[i : i + 4][::-1] in normalized
        for row in rows
        for i in range(len(row) - 3)
    ):
        patterns.append("keyboard_or_numeric_sequence")
    root = re.sub(r"[\d\W_]+$", "", normalized)
    translated = root.translate(str.maketrans("@01!$357", "aoiisest"))
    if any(word in translated for word in COMMON):
        patterns.append("common_dictionary_fragment_or_substitution")
    if any(word.casefold() in normalized for word in context if len(word) >= 3):
        patterns.append("context_specific_word")
    if re.search(r"(?:19|20)\d{2}[!@#$%^&*?.]*$", normalized):
        patterns.append("year_suffix")
    if re.search(r"(?:summer|winter|spring|autumn|fall|лето|зима|весна|осень)", normalized):
        patterns.append("season_pattern")
    score = max(0, min(4, len(value) // 5) - min(3, len(patterns)))
    return {
        "length": len(value),
        "heuristic_score": score,
        "score_maximum": 4,
        "patterns": patterns,
        "dictionary_resistance": "review" if patterns else "no listed pattern",
        "limitations": "Not entropy, crack time, breach detection or proof of strength.",
    }


def audit_dataset(dataset: PasswordDataset) -> ModuleResult:
    result = ModuleResult(module="passwords", target="synthetic-dataset")
    result.findings.extend(audit_policy(dataset.policy, "synthetic-policy"))
    minimum = dataset.policy.minimum_length or (8 if dataset.policy.mfa_required else 15)
    assessments = []
    for sample in dataset.samples:
        analysis = assess_sample(sample.value.get_secret_value(), dataset.context_words, minimum)
        assessments.append({"sample_id": sample.id, **analysis})
        if analysis["patterns"]:
            result.findings.append(
                finding(
                    "passwords",
                    sample.id,
                    "synthetic-pattern",
                    "Synthetic sample has predictable patterns",
                    Severity.LOW,
                    "This is a laboratory result, not a finding about a production credential.",
                    {
                        "sample_id": sample.id,
                        "patterns": analysis["patterns"],
                        "length": analysis["length"],
                    },
                    "Prefer a unique randomly generated password or passphrase, enforce blocklists and use MFA.",
                    "CWE-521",
                    [NIST_PASSWORDS],
                )
            )
    result.observations = {
        "synthetic": True,
        "samples": assessments,
        "policy": dataset.policy.model_dump(exclude_none=True),
        "unknown_policy_fields": [
            k for k in PasswordPolicy.model_fields if getattr(dataset.policy, k) is None
        ],
        "values_or_hashes_stored": False,
    }
    return result


def synthetic_lab() -> PasswordDataset:
    return PasswordDataset(
        synthetic=True,
        policy=PasswordPolicy(
            minimum_length=8,
            maximum_length=32,
            mfa_required=False,
            blocklist_enabled=False,
            rate_limit_enabled=True,
        ),
        samples=[
            Sample(id="common-substitution", value=SecretStr("P@ssw0rd2026!")),
            Sample(id="numeric-sequence", value=SecretStr("1234567890")),
            Sample(id="repeated", value=SecretStr("abcabcabcabc")),
            Sample(id="passphrase", value=SecretStr("cedar-orbit-saffron-mosaic")),
        ],
    )
