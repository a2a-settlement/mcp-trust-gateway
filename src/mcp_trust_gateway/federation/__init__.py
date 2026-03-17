"""Federation module for the MCP Trust Gateway.

Implements the Trust Discount engine, health monitoring, and policy
advertisement for the A2A-SE federation protocol.
"""

from .trust_discount import (
    TrustDiscountAlgorithm,
    TrustDiscountInputs,
    TrustDiscountResult,
    LinearVolumeWeightedV1,
    StepFunctionV1,
    ExponentialDecayV1,
)
from .registry import AlgorithmRegistry
from .health_monitor import FederationHealthMonitor, PeerHealthStatus

__all__ = [
    "TrustDiscountAlgorithm",
    "TrustDiscountInputs",
    "TrustDiscountResult",
    "LinearVolumeWeightedV1",
    "StepFunctionV1",
    "ExponentialDecayV1",
    "AlgorithmRegistry",
    "FederationHealthMonitor",
    "PeerHealthStatus",
]
