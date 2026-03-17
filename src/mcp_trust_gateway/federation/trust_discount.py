"""Pluggable Trust Discount algorithm engine.

Implements the Trust Discount interface defined in the A2A-SE Federation
Protocol (Section 03). Ships three built-in algorithms matching the
algorithm registry.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TrustDiscountInputs:
    """Mandatory telemetry inputs for Trust Discount computation.

    All federated A2A-SE nodes MUST expose these metrics to their peers.
    """

    federation_age_days: int
    cross_exchange_volume_ate: float
    cross_exchange_tx_count: int
    attestation_success_rate: float

    # Recommended extension inputs
    peer_stake_slashing_events: Optional[int] = None
    uptime_90d: Optional[float] = None
    avg_attestation_latency_ms: Optional[int] = None


@dataclass
class TrustDiscountResult:
    """Output of a Trust Discount computation."""

    rho: float
    algorithm_id: str
    inputs: TrustDiscountInputs
    details: dict = field(default_factory=dict)

    def __post_init__(self):
        self.rho = max(0.0, min(1.0, self.rho))


class TrustDiscountAlgorithm(ABC):
    """Abstract base class for Trust Discount algorithms.

    Implementations must:
    1. Accept the four mandatory input fields
    2. Output a single float rho in [0.0, 1.0]
    3. Be monotonically non-decreasing with respect to volume
    4. Produce rho = 0.0 when all mandatory inputs are zero
    """

    @property
    @abstractmethod
    def algorithm_id(self) -> str:
        """URN identifying this algorithm."""

    @abstractmethod
    def compute_rho(
        self, inputs: TrustDiscountInputs, params: dict[str, Any]
    ) -> TrustDiscountResult:
        """Compute the Trust Discount multiplier rho."""


class LinearVolumeWeightedV1(TrustDiscountAlgorithm):
    """urn:a2a:trust:discount:linear-volume-weighted-v1

    Rho increases linearly with cross-exchange settlement volume,
    gated by attestation success rate.
    """

    @property
    def algorithm_id(self) -> str:
        return "urn:a2a:trust:discount:linear-volume-weighted-v1"

    def compute_rho(
        self, inputs: TrustDiscountInputs, params: dict[str, Any]
    ) -> TrustDiscountResult:
        floor = params.get("attestation_success_floor", 0.92)
        if inputs.attestation_success_rate < floor:
            return TrustDiscountResult(
                rho=0.0,
                algorithm_id=self.algorithm_id,
                inputs=inputs,
                details={"reason": "attestation_success_below_floor"},
            )

        age_factor = min(inputs.federation_age_days / 365.0, 1.0) * 0.1

        volume_threshold = params.get("volume_threshold_ate", 10000)
        rho_at_threshold = params.get("rho_at_threshold", 0.40)
        max_rho = params.get("max_rho", 0.85)

        if inputs.cross_exchange_volume_ate <= 0:
            volume_rho = 0.0
        elif inputs.cross_exchange_volume_ate >= volume_threshold:
            volume_rho = rho_at_threshold
        else:
            volume_rho = (
                inputs.cross_exchange_volume_ate / volume_threshold
            ) * rho_at_threshold

        raw_rho = age_factor + volume_rho
        rho = min(raw_rho, max_rho)

        return TrustDiscountResult(
            rho=rho,
            algorithm_id=self.algorithm_id,
            inputs=inputs,
            details={
                "age_factor": age_factor,
                "volume_rho": volume_rho,
                "raw_rho": raw_rho,
                "capped": raw_rho > max_rho,
            },
        )


class StepFunctionV1(TrustDiscountAlgorithm):
    """urn:a2a:trust:discount:step-function-v1

    Rho increases in discrete steps as federation milestones are reached.
    """

    @property
    def algorithm_id(self) -> str:
        return "urn:a2a:trust:discount:step-function-v1"

    def compute_rho(
        self, inputs: TrustDiscountInputs, params: dict[str, Any]
    ) -> TrustDiscountResult:
        floor = params.get("attestation_success_floor", 0.95)
        if inputs.attestation_success_rate < floor:
            return TrustDiscountResult(
                rho=0.0,
                algorithm_id=self.algorithm_id,
                inputs=inputs,
                details={"reason": "attestation_success_below_floor"},
            )

        steps = params.get("steps", [])
        matched_step = None
        for step in reversed(steps):
            if (
                inputs.federation_age_days >= step.get("min_age_days", 0)
                and inputs.cross_exchange_volume_ate
                >= step.get("min_volume_ate", 0)
                and inputs.cross_exchange_tx_count
                >= step.get("min_tx_count", 0)
            ):
                matched_step = step
                break

        rho = matched_step["rho"] if matched_step else 0.0

        return TrustDiscountResult(
            rho=rho,
            algorithm_id=self.algorithm_id,
            inputs=inputs,
            details={
                "matched_step": matched_step,
                "total_steps": len(steps),
            },
        )


class ExponentialDecayV1(TrustDiscountAlgorithm):
    """urn:a2a:trust:discount:exponential-decay-v1

    Rho approaches max_rho asymptotically with diminishing returns
    on additional volume.
    """

    @property
    def algorithm_id(self) -> str:
        return "urn:a2a:trust:discount:exponential-decay-v1"

    def compute_rho(
        self, inputs: TrustDiscountInputs, params: dict[str, Any]
    ) -> TrustDiscountResult:
        floor = params.get("attestation_success_floor", 0.90)
        if inputs.attestation_success_rate < floor:
            return TrustDiscountResult(
                rho=0.0,
                algorithm_id=self.algorithm_id,
                inputs=inputs,
                details={"reason": "attestation_success_below_floor"},
            )

        max_rho = params.get("max_rho", 0.85)
        half_life = params.get("volume_half_life_ate", 5000)
        age_weight = params.get("age_weight", 0.1)

        age_component = min(inputs.federation_age_days / 365.0, 1.0) * age_weight

        volume_ceiling = max_rho - age_weight
        if inputs.cross_exchange_volume_ate <= 0:
            volume_component = 0.0
        else:
            k = math.log(2) / half_life
            volume_component = volume_ceiling * (
                1.0 - math.exp(-k * inputs.cross_exchange_volume_ate)
            )

        rho = min(age_component + volume_component, max_rho)

        return TrustDiscountResult(
            rho=rho,
            algorithm_id=self.algorithm_id,
            inputs=inputs,
            details={
                "age_component": age_component,
                "volume_component": volume_component,
                "volume_ceiling": volume_ceiling,
            },
        )
