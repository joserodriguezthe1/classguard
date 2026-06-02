"""
Aggregator: combines the deterministic rules floor with the Bedrock AI layer.

This is the ONE place that enforces the core control:

    the AI may RAISE the sensitivity tier, never lower it.

Keeping that rule in a single short function means an assessor can read this
file and verify the property directly, instead of tracing it through the model
code. Low-confidence AI raises are suppressed and flagged for human review
rather than applied automatically (human-in-the-loop for uncertain decisions).
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import rules
import bedrock

log = logging.getLogger()

# An AI upgrade applies automatically only at or above this confidence.
# Below it, the rules floor stands and the object is flagged for human review.
AI_CONFIDENCE_THRESHOLD = float(os.environ.get("AI_CONFIDENCE_THRESHOLD", "0.6"))


@dataclass
class Classification:
    tier: str
    impact: str
    cui: bool
    categories: List[str] = field(default_factory=list)
    findings: Dict[str, int] = field(default_factory=dict)
    ai_available: bool = False
    ai_tier: Optional[str] = None
    ai_confidence: float = 0.0
    ai_rationale: str = ""
    review_recommended: bool = False
    decided_by: str = "rules"

    def as_tags(self) -> Dict[str, str]:
        """Values safe to attach as S3 object tags / metadata (no raw sensitive data)."""
        return {
            "classification": self.tier,
            "impact-level": self.impact,
            "cui": "true" if self.cui else "false",
            "categories": ",".join(sorted(set(self.categories))) or "none",
            "review": "true" if self.review_recommended else "false",
        }


def _higher(a: str, b: str) -> str:
    """Return the more sensitive of two tiers. This comparison is the 'never lower' rule."""
    return a if rules.TIER_ORDER.index(a) >= rules.TIER_ORDER.index(b) else b


def classify(text: str) -> Classification:
    floor = rules.scan(text)

    result = Classification(
        tier=floor.tier,
        impact=rules.TIER_IMPACT[floor.tier],
        cui=floor.cui,
        categories=list(floor.categories),
        findings=dict(floor.findings),
        decided_by="rules",
    )

    ai = bedrock.classify(text, floor_categories=floor.categories)
    result.ai_available = ai.available
    result.ai_confidence = ai.confidence
    result.ai_rationale = ai.rationale

    if not ai.available:
        return result  # rules-only; the floor stands

    result.ai_tier = ai.tier

    # CUI is sticky upward: once either layer flags it, it stays flagged.
    if ai.cui and not result.cui:
        result.cui = True
        if "CUI" not in result.categories:
            result.categories.append("CUI")

    # The core rule: the AI's tier only counts if it is higher than the floor.
    proposed = _higher(floor.tier, ai.tier)
    if proposed == floor.tier:
        # AI agreed or tried to go lower -> floor stands, AI cannot weaken it.
        result.decided_by = "rules+ai"
    elif ai.confidence >= AI_CONFIDENCE_THRESHOLD:
        # Confident upgrade -> apply it.
        result.tier = proposed
        result.impact = rules.TIER_IMPACT[proposed]
        result.decided_by = "ai-raised"
    else:
        # Wants to upgrade but isn't confident enough -> keep floor, ask a human.
        result.review_recommended = True
        result.decided_by = "rules+ai-low-confidence"

    return result
