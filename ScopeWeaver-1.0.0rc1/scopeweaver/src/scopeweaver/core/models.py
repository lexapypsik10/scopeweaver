from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from scopeweaver import __version__


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Finding(StrictModel):
    id: str
    module: str
    target: str
    title: str
    severity: Severity
    description: str
    evidence: dict[str, Any]
    remediation: str
    references: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cvss: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    confidence: str = "observed configuration; impact needs contextual review"


def finding(
    module: str,
    target: str,
    rule: str,
    title: str,
    severity: Severity,
    description: str,
    evidence: dict[str, Any],
    remediation: str,
    cwe: str = "CWE-16",
    references: list[str] | None = None,
) -> Finding:
    digest = hashlib.sha256(f"{module}|{target}|{rule}".encode()).hexdigest()[:16]
    return Finding(
        id=f"SW-{digest}",
        module=module,
        target=target,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=[cwe],
        references=references or [f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html"],
    )


class Service(StrictModel):
    host: str
    ip: str
    port: int = Field(ge=1, le=65535)
    transport: str = "tcp"
    state: str
    name: str = "unknown"
    detection: str = "not identified"
    banner: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModuleResult(StrictModel):
    module: str
    target: str
    status: str = "completed"
    findings: list[Finding] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    observations: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class Assessment(StrictModel):
    schema_version: str = "1.0"
    tool: str = "ScopeWeaver"
    version: str = __version__
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    results: list[ModuleResult] = Field(default_factory=list)
    interrupted: bool = False
    network_operations: int = 0

    @property
    def findings(self) -> list[Finding]:
        unique = {f.id: f for result in self.results for f in result.findings}
        order = list(Severity)
        return sorted(unique.values(), key=lambda f: (order.index(f.severity), f.target, f.id))

    @property
    def statistics(self) -> dict[str, int]:
        return {s.value: sum(f.severity == s for f in self.findings) for s in Severity}
