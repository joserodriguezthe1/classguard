"""
Pattern-based detection rules for ClassGuard.

Design principle: detection results record the *type* and *count* of matches,
never the raw matched string. A classification tool that logs the SSNs it finds
just becomes a second copy of the exposure it was meant to prevent.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List

# Sensitivity tiers, ordered low -> high. The classifier picks the highest tier
# implied by any single detection.
PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED = "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"
TIER_ORDER = [PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED]

# FIPS-199 impact level associated with each tier.
TIER_IMPACT = {PUBLIC: "LOW", INTERNAL: "LOW", CONFIDENTIAL: "MODERATE", RESTRICTED: "HIGH"}


def _luhn_valid(value: str) -> bool:
    """Reject digit strings that look like cards but fail the checksum (cuts false positives)."""
    digits = [int(c) for c in re.sub(r"\D", "", value)]
    if len(digits) < 13:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# CUI / federal marking banners. Treated as an explicit, author-asserted control marking.
CUI_MARKERS = re.compile(
    r"\b(CONTROLLED UNCLASSIFIED INFORMATION|CUI//|CUI|FOUO|NOFORN|"
    r"FOR OFFICIAL USE ONLY|LAW ENFORCEMENT SENSITIVE|SBU)\b",
    re.IGNORECASE,
)


@dataclass
class Detector:
    name: str
    pattern: re.Pattern
    category: str          # PII | FINANCIAL | SECRET | NETWORK
    tier: str              # minimum sensitivity tier this detection implies
    validate: callable = None


DETECTORS: List[Detector] = [
    Detector("US_SSN",
             re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
             "PII", CONFIDENTIAL),
    Detector("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,16}\b"),
             "FINANCIAL", CONFIDENTIAL, validate=_luhn_valid),
    Detector("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
             "PII", INTERNAL),
    Detector("US_PHONE", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
             "PII", INTERNAL),
    Detector("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
             "SECRET", RESTRICTED),
    Detector("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
             "SECRET", RESTRICTED),
    Detector("GENERIC_SECRET",
             re.compile(r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*\S{6,}"),
             "SECRET", RESTRICTED),
]


@dataclass
class ScanResult:
    tier: str = PUBLIC
    cui: bool = False
    findings: Dict[str, int] = field(default_factory=dict)   # detector_name -> count
    categories: List[str] = field(default_factory=list)

    def as_metadata(self) -> Dict[str, str]:
        """Flatten to string values safe for S3 object tags / metadata."""
        return {
            "classification": self.tier,
            "impact-level": TIER_IMPACT[self.tier],
            "cui": "true" if self.cui else "false",
            "categories": ",".join(sorted(set(self.categories))) or "none",
        }


def _raise_tier(current: str, candidate: str) -> str:
    """Return whichever tier is more sensitive. This is the 'highest wins' rule."""
    return candidate if TIER_ORDER.index(candidate) > TIER_ORDER.index(current) else current


def scan(text: str) -> ScanResult:
    """Run all deterministic detectors and return the aggregated floor result."""
    result = ScanResult()

    if CUI_MARKERS.search(text):
        result.cui = True
        result.categories.append("CUI")
        result.tier = _raise_tier(result.tier, CONFIDENTIAL)

    for det in DETECTORS:
        matches = det.pattern.findall(text)
        if det.validate:
            matches = [m for m in matches if det.validate(m if isinstance(m, str) else "".join(m))]
        if not matches:
            continue
        result.findings[det.name] = len(matches)   # count only — never the value
        result.categories.append(det.category)
        result.tier = _raise_tier(result.tier, det.tier)

    return result
