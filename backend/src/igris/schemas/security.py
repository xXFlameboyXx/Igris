"""Schemas for Phase 17 Security Hardening and Machine-Readable Security Review."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class SecuritySeverity(StrEnum):
    """Categorical severity rating for identified security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingStatus(StrEnum):
    """Lifecycle status of an identified security finding."""

    CONFIRMED_VULNERABILITY = "CONFIRMED_VULNERABILITY"
    RESOLVED_FINDING = "RESOLVED_FINDING"
    OBSERVED_LIMITATION = "OBSERVED_LIMITATION"
    THEORETICAL_RISK = "THEORETICAL_RISK"
    DEPLOYMENT_ASSUMPTION = "DEPLOYMENT_ASSUMPTION"


class SecurityFinding(BaseModel):
    """Structured security finding record."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    severity: SecuritySeverity
    status: FindingStatus
    affected_component: str
    attack_preconditions: str
    attacker_controlled_input: str
    impact: str
    reproduction_status: str
    evidence: str
    root_cause: str
    remediation: str
    regression_test: str
    residual_risk: str


class SecurityTestResult(BaseModel):
    """Result of an automated security regression or fuzzing test."""

    model_config = ConfigDict(extra="forbid")

    test_name: str
    category: str
    passed: bool
    description: str


class ScannerResult(BaseModel):
    """Report from a static or dynamic security scanner."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    version: str
    command: str
    findings_count: int
    accepted_count: int
    notes: str


class SecurityReviewRecord(BaseModel):
    """Complete, machine-readable Phase 17 security assessment review."""

    model_config = ConfigDict(extra="forbid")

    review_id: str = Field(default_factory=lambda: f"sec-rev-{uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    code_version: str = "0.1.0"
    configuration_version: str = "v1"
    findings: list[SecurityFinding] = Field(default_factory=list)
    security_test_results: list[SecurityTestResult] = Field(default_factory=list)
    scanner_results: list[ScannerResult] = Field(default_factory=list)
    components_reviewed: list[str] = Field(default_factory=list)
    residual_risks: list[str] = Field(default_factory=list)
    deployment_assumptions: list[str] = Field(default_factory=list)
    overall_assessment: Literal[
        "SECURITY REVIEW COMPLETE — HARDENED WITH DOCUMENTED RESIDUAL RISK",
        "SECURITY REVIEW IN PROGRESS",
    ] = "SECURITY REVIEW COMPLETE — HARDENED WITH DOCUMENTED RESIDUAL RISK"
