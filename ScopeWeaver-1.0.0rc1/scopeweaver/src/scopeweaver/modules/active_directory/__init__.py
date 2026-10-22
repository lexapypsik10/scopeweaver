from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from scopeweaver.core.models import ModuleResult, Severity, StrictModel, finding
from scopeweaver.modules.passwords import PasswordPolicy, audit_policy

MS_FLAGS = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties"
MS_DELEGATION = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
MS_RC4 = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos"


class ADAccount(StrictModel):
    id: str = Field(min_length=1, max_length=1024)
    name: str = Field(min_length=1, max_length=256)
    kind: Literal["user", "computer", "service", "domain_controller"] = "user"
    enabled: bool
    user_account_control: int = Field(ge=0)
    encryption_types: int | None = Field(default=None, ge=0)
    admin_count: int | None = Field(default=None, ge=0)
    spns: list[str] = Field(default_factory=list, max_length=1000)
    allowed_to_delegate_to: list[str] = Field(default_factory=list, max_length=1000)
    rbcd_principals: list[str] = Field(default_factory=list, max_length=1000)


class ADGroup(StrictModel):
    id: str = Field(min_length=1, max_length=1024)
    name: str = Field(min_length=1, max_length=256)
    privileged: bool
    members: list[str] = Field(default_factory=list, max_length=100000)


class ADPermission(StrictModel):
    principal: str = Field(min_length=1, max_length=1024)
    target: str = Field(min_length=1, max_length=1024)
    rights: list[str] = Field(min_length=1, max_length=100)
    access_type: Literal["Allow", "Deny"]
    privileged_target: bool
    # This is a normalized ACE review, not an effective Windows access-check engine.


class ADExport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    domain: str = Field(min_length=1, max_length=253)
    policy: PasswordPolicy
    accounts: list[ADAccount] = Field(default_factory=list, max_length=100000)
    groups: list[ADGroup] = Field(default_factory=list, max_length=10000)
    permissions: list[ADPermission] = Field(default_factory=list, max_length=100000)
    collection_notes: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def unique_objects(self) -> Self:
        ids = [a.id for a in self.accounts] + [g.id for g in self.groups]
        if len(ids) != len(set(ids)):
            raise ValueError("account and group IDs must be globally unique")
        return self


def audit_export(export: ADExport) -> ModuleResult:
    result = ModuleResult(module="ad", target=export.domain)
    result.findings.extend(audit_policy(export.policy, export.domain, "ad"))
    groups = {g.id: g for g in export.groups}
    accounts = {a.id: a for a in export.accounts}
    memberships: dict[str, list[str]] = {}
    privileged_ids: set[str] = set()
    unknown: set[str] = set()
    cycles: set[str] = set()
    for group in export.groups:
        if not group.privileged:
            continue
        members: set[str] = set()
        visited: set[str] = set()
        pending = [group.id]
        while pending:
            gid = pending.pop()
            if gid in visited:
                cycles.add(gid)
                continue
            visited.add(gid)
            for member in groups[gid].members:
                if member in groups:
                    pending.append(member)
                elif member in accounts:
                    members.add(member)
                else:
                    unknown.add(member)
        memberships[group.id] = sorted(members)
        privileged_ids.update(members)
        if len(members) > 10:
            result.findings.append(
                finding(
                    "ad",
                    group.id,
                    "privileged-count",
                    "Privileged group membership needs justification",
                    Severity.INFO,
                    "More than ten transitive members were found; this is a review threshold, "
                    "not proof of excess privileges.",
                    {"group": group.name, "member_count": len(members), "review_threshold": 10},
                    "Validate business need for each privileged member and use separate administrative accounts.",
                    "CWE-269",
                    [MS_DELEGATION],
                )
            )

    for account in export.accounts:
        if not account.enabled:
            continue
        uac = account.user_account_control

        def add(
            rule: str,
            title: str,
            severity: Severity,
            description: str,
            evidence: dict[str, object],
            remedy: str,
            cwe: str = "CWE-269",
            ref: str = MS_FLAGS,
            account_id: str = account.id,
        ) -> None:
            result.findings.append(
                finding(
                    "ad",
                    account_id,
                    rule,
                    title,
                    severity,
                    description,
                    evidence,
                    remedy,
                    cwe,
                    [ref],
                )
            )

        if uac & 0x400000:
            add(
                "preauth",
                "Kerberos pre-authentication is disabled",
                Severity.HIGH,
                "An enabled account is configured not to require Kerberos pre-authentication.",
                {"account": account.name, "flag": "DONT_REQ_PREAUTH"},
                "Require Kerberos pre-authentication and review the exception owner.",
                "CWE-287",
            )
        if uac & 0x20:
            add(
                "password-not-required",
                "Password requirement flag is disabled",
                Severity.MEDIUM,
                "PASSWD_NOTREQD is set. This flag alone does not establish a blank password.",
                {"account": account.name, "flag": "PASSWD_NOTREQD"},
                "Clear PASSWD_NOTREQD after validating application compatibility.",
                "CWE-521",
            )
        is_dc = account.kind == "domain_controller" or bool(uac & 0x2000)
        if uac & 0x80000 and not is_dc:
            add(
                "unconstrained",
                "Unconstrained delegation configured",
                Severity.HIGH,
                "An enabled non-domain-controller account trusts unconstrained delegation.",
                {"account": account.name, "flag": "TRUSTED_FOR_DELEGATION"},
                "Remove unconstrained delegation and use narrowly scoped delegation where required.",
                ref=MS_DELEGATION,
            )
        if uac & 0x1000000:
            add(
                "protocol-transition",
                "Delegation permits protocol transition",
                Severity.MEDIUM,
                "The account is trusted to authenticate for delegation; validate all delegated services.",
                {"account": account.name, "allowed_to_delegate_to": account.allowed_to_delegate_to},
                "Remove protocol transition if unused and limit delegation targets.",
                ref=MS_DELEGATION,
            )
        if account.allowed_to_delegate_to or account.rbcd_principals:
            add(
                "delegation-review",
                "Delegation relationships require review",
                Severity.INFO,
                "Configured delegation is inventoried for an explicit least-privilege review.",
                {
                    "allowed_to_delegate_to": account.allowed_to_delegate_to,
                    "rbcd_principals": account.rbcd_principals,
                },
                "Document approved delegation paths and remove unused relationships.",
                ref=MS_DELEGATION,
            )
        enc = account.encryption_types
        if uac & 0x200000 or enc is not None and enc & 0x3:
            add(
                "des",
                "DES Kerberos encryption permitted",
                Severity.HIGH,
                "An explicit account setting permits obsolete DES encryption.",
                {"user_account_control": uac, "encryption_types": enc},
                "Remove DES after validating AES support and keys.",
                "CWE-327",
                MS_RC4,
            )
        if enc is not None and enc & 0x4 and not enc & 0x18:
            add(
                "rc4-without-aes",
                "RC4 permitted without AES account support",
                Severity.MEDIUM,
                "The explicit encryption bitmask allows RC4 without AES bits. "
                "Actual ticket encryption also depends on KDC policy and available keys.",
                {"encryption_types": enc},
                "Migrate services to AES, validate keys and disable RC4.",
                "CWE-327",
                MS_RC4,
            )
        if account.id in privileged_ids:
            if not uac & 0x100000:
                add(
                    "privileged-delegatable",
                    "Privileged account is not marked non-delegatable",
                    Severity.MEDIUM,
                    "A transitive privileged group member lacks NOT_DELEGATED. "
                    "Other protections such as Protected Users were not evaluated.",
                    {"account": account.name, "privileged_membership": True},
                    "Validate protected-user controls and enable Account is sensitive and cannot be delegated.",
                )
            if account.spns:
                add(
                    "privileged-service",
                    "Service account has privileged group membership",
                    Severity.HIGH,
                    "An enabled account with SPNs is a transitive member of a privileged group.",
                    {"account": account.name, "spns": account.spns},
                    "Separate service identities from administrative privileges and evaluate gMSA.",
                )
        elif account.admin_count == 1:
            add(
                "stale-admincount",
                "adminCount requires protection review",
                Severity.INFO,
                "adminCount is set but no privileged membership exists in this export. "
                "Incomplete group collection can also explain this observation.",
                {"admin_count": 1},
                "Review historical privileges, complete group coverage and ACL inheritance.",
            )

    dangerous = {
        "genericall",
        "genericwrite",
        "writedacl",
        "writeowner",
        "forcechangepassword",
        "ds-replication-get-changes",
        "ds-replication-get-changes-all",
    }
    for index, permission in enumerate(export.permissions):
        rights = sorted({r.casefold() for r in permission.rights} & dangerous)
        if permission.access_type == "Allow" and permission.privileged_target and rights:
            broad = permission.principal in {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}
            result.findings.append(
                finding(
                    "ad",
                    permission.target,
                    f"permission-{index}",
                    "Sensitive permission on privileged object",
                    Severity.HIGH if broad else Severity.MEDIUM,
                    "A normalized Allow ACE grants a sensitive right. Effective access is not calculated; "
                    "deny ACEs, inheritance, object-specific GUIDs and group tokens require manual review.",
                    {
                        "principal": permission.principal,
                        "rights": rights,
                        "effective_access_verified": False,
                        "broad_builtin_principal": broad,
                    },
                    "Verify effective access and remove permissions without an approved administrative purpose.",
                    "CWE-732",
                    ["https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control"],
                )
            )
    result.observations = {
        "account_count": len(accounts),
        "group_count": len(groups),
        "permission_count": len(export.permissions),
        "transitive_privileged_members": memberships,
        "unresolved_members": sorted(unknown),
        "revisited_group_nodes": sorted(cycles),
        "unknown_encryption_accounts": [a.id for a in export.accounts if not a.encryption_types],
        "collection_notes": export.collection_notes,
        "limitations": "Offline snapshot; no effective ACL evaluation, "
        "fine-grained resultant policies or complete attack-path modeling.",
    }
    if unknown:
        result.status = "partial"
        result.errors.append(
            "Some group members are absent from this export; membership is incomplete."
        )
    return result
