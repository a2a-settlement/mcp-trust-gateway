"""EMA-weighted trust decay for delegation chains.

Each delegation hop multiplies effective trust by a decay factor,
ensuring authority diminishes as it travels from the original principal.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import get_trust_decay_factor, get_max_delegation_depth


@dataclass(frozen=True)
class TrustScore:
    """Computed trust score with provenance metadata."""

    reputation: float
    kya_level: int
    delegation_depth: int
    decay_factor: float
    effective_trust: float

    @property
    def summary(self) -> dict:
        return {
            "reputation": round(self.reputation, 4),
            "kya_level": self.kya_level,
            "delegation_depth": self.delegation_depth,
            "decay_factor": self.decay_factor,
            "effective_trust": round(self.effective_trust, 4),
        }


def compute_effective_trust(
    reputation: float,
    delegation_depth: int = 0,
    decay_factor: float | None = None,
) -> float:
    """Compute the effective trust score after delegation decay.

    effective_trust = reputation × decay_factor ^ delegation_depth
    """
    if decay_factor is None:
        decay_factor = get_trust_decay_factor()
    reputation = max(0.0, min(1.0, reputation))
    if delegation_depth <= 0:
        return reputation
    return reputation * (decay_factor ** delegation_depth)


def compute_trust_score(
    reputation: float,
    kya_level: int,
    delegation_depth: int = 0,
    decay_factor: float | None = None,
) -> TrustScore:
    """Build a full TrustScore from agent attributes."""
    if decay_factor is None:
        decay_factor = get_trust_decay_factor()
    effective = compute_effective_trust(reputation, delegation_depth, decay_factor)
    return TrustScore(
        reputation=reputation,
        kya_level=kya_level,
        delegation_depth=delegation_depth,
        decay_factor=decay_factor,
        effective_trust=effective,
    )


def apply_delegation_decay(parent_trust: TrustScore) -> TrustScore:
    """Compute the trust score for a child after one delegation hop."""
    max_depth = get_max_delegation_depth()
    new_depth = parent_trust.delegation_depth + 1
    if new_depth > max_depth:
        return TrustScore(
            reputation=parent_trust.reputation,
            kya_level=parent_trust.kya_level,
            delegation_depth=new_depth,
            decay_factor=parent_trust.decay_factor,
            effective_trust=0.0,
        )
    new_effective = parent_trust.effective_trust * parent_trust.decay_factor
    return TrustScore(
        reputation=parent_trust.reputation,
        kya_level=parent_trust.kya_level,
        delegation_depth=new_depth,
        decay_factor=parent_trust.decay_factor,
        effective_trust=max(0.0, new_effective),
    )
