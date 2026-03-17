"""Trust Discount algorithm registry.

Maps algorithm URNs to implementation classes. Mirrors the append-only
registry defined in the a2a-federation-rfc repository.
"""

from __future__ import annotations

from typing import Optional

from .trust_discount import (
    TrustDiscountAlgorithm,
    LinearVolumeWeightedV1,
    StepFunctionV1,
    ExponentialDecayV1,
)

_BUILTIN_ALGORITHMS: dict[str, type[TrustDiscountAlgorithm]] = {
    "urn:a2a:trust:discount:linear-volume-weighted-v1": LinearVolumeWeightedV1,
    "urn:a2a:trust:discount:step-function-v1": StepFunctionV1,
    "urn:a2a:trust:discount:exponential-decay-v1": ExponentialDecayV1,
}


class AlgorithmRegistry:
    """Registry of Trust Discount algorithms.

    Pre-loaded with the three built-in algorithms from the federation spec.
    Additional algorithms can be registered at runtime.
    """

    def __init__(self):
        self._algorithms: dict[str, TrustDiscountAlgorithm] = {}
        for urn, cls in _BUILTIN_ALGORITHMS.items():
            self._algorithms[urn] = cls()

    def get(self, algorithm_id: str) -> Optional[TrustDiscountAlgorithm]:
        """Look up an algorithm by URN."""
        return self._algorithms.get(algorithm_id)

    def register(
        self, algorithm: TrustDiscountAlgorithm
    ) -> None:
        """Register a custom algorithm implementation."""
        self._algorithms[algorithm.algorithm_id] = algorithm

    def list_algorithms(self) -> list[str]:
        """Return all registered algorithm URNs."""
        return list(self._algorithms.keys())

    def has(self, algorithm_id: str) -> bool:
        return algorithm_id in self._algorithms
