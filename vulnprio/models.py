"""Shared constants, data classes and the user-facing error type (SPEC.md section 2).

Provided with the specification: keep this file unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, Optional, Tuple


class VulnprioError(Exception):
    """A user-facing input or data error (the CLI prints it as 'error: <message>')."""


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

STRATEGIES = ("CVSS_CRITICAL", "CVSS_HIGH_PLUS", "EPSS_EFFORT_MATCHED", "EPSS_THRESHOLD")

EFFORT_LEVELS_PCT = (1, 2, 5, 10, 20, 30, 50, 100)

TIERS = ("P1", "P2", "P3", "P4")

REASON_CODES = (
    "KEV",
    "RANSOMWARE",
    "EPSS_HIGH",
    "CRITICAL_INTERNET_FACING",
    "CVSS_CRITICAL",
    "CVSS_HIGH",
    "EPSS_MEDIUM",
    "UNKNOWN_CVE",
    "ESCALATED_ASSET_CRITICALITY",
)

REASON_TEXT = {
    "KEV": "Listed in CISA KEV (known exploited)",
    "RANSOMWARE": "Known use in ransomware campaigns",
    "EPSS_HIGH": "High exploitation probability (EPSS)",
    "CRITICAL_INTERNET_FACING": "Critical severity on an internet-facing asset",
    "CVSS_CRITICAL": "Critical CVSS severity",
    "CVSS_HIGH": "High CVSS severity",
    "EPSS_MEDIUM": "Elevated exploitation probability (EPSS)",
    "UNKNOWN_CVE": "Not found in the loaded NVD or EPSS data",
    "ESCALATED_ASSET_CRITICALITY": "Escalated: high-criticality asset",
}

# (label, lowest lag in days or None, highest lag in days or None), inclusive.
LAG_BUCKETS = (
    ("<=0", None, 0),
    ("1-7", 1, 7),
    ("8-30", 8, 30),
    ("31-90", 31, 90),
    ("91-365", 91, 365),
    (">365", 366, None),
)

CVSS_BANDS = ("critical", "high", "medium", "low", "none", "unscored")


def cvss_band(score: Optional[float]) -> str:
    """Map a CVSS v3 base score to its severity band (None means not scored)."""
    if score is None:
        return "unscored"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    published: date
    vuln_status: str
    cvss_score: Optional[float]
    cvss_version: Optional[str]
    cvss_source_type: Optional[str]
    cwes: Tuple[str, ...] = ()


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor: str
    product: str
    date_added: date
    ransomware: bool
    cwes: Tuple[str, ...] = ()


@dataclass(frozen=True)
class EpssSnapshot:
    snapshot_date: date
    model_version: Optional[str]
    scores: Dict[str, float] = field(default_factory=dict)
    percentiles: Dict[str, float] = field(default_factory=dict)
    skipped_rows: int = 0


@dataclass(frozen=True)
class Finding:
    asset_id: str
    cve_id: str
    asset_criticality: str = "medium"
    internet_facing: bool = False


@dataclass(frozen=True)
class BacktestConfig:
    lookback_days: int = 730
    horizon_days: int = 365
    epss_threshold: float = 0.1
    bootstrap_iterations: int = 1000
    seed: int = 42
    confidence: float = 0.95


@dataclass(frozen=True)
class TriageConfig:
    epss_high: float = 0.1
    epss_medium: float = 0.01
    cvss_critical: float = 9.0
    cvss_high: float = 7.0
