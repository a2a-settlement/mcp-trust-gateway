"""Well-known federation endpoints for the MCP Trust Gateway.

Serves ``/.well-known/a2a-trust-policy.json`` with the exchange's current
Trust Discount policy parameters.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse


class FederationWellKnown:
    """Serves federation well-known endpoints."""

    def __init__(
        self,
        algorithm_id: str = "urn:a2a:trust:discount:linear-volume-weighted-v1",
        initial_rho: float = 0.15,
        parameters: dict | None = None,
    ):
        self._policy = {
            "algorithm_id": algorithm_id,
            "initial_rho": initial_rho,
            "parameters": parameters or {
                "volume_threshold_ate": 10000,
                "rho_at_threshold": 0.40,
                "max_rho": 0.85,
                "attestation_success_floor": 0.92,
                "review_cadence_days": 30,
            },
        }

    def update_policy(
        self,
        algorithm_id: str | None = None,
        initial_rho: float | None = None,
        parameters: dict | None = None,
    ) -> None:
        if algorithm_id is not None:
            self._policy["algorithm_id"] = algorithm_id
        if initial_rho is not None:
            self._policy["initial_rho"] = initial_rho
        if parameters is not None:
            self._policy["parameters"] = parameters

    @property
    def policy(self) -> dict:
        return dict(self._policy)

    async def handle_trust_policy(self, request: Request) -> JSONResponse:
        """Handle GET /.well-known/a2a-trust-policy.json"""
        return JSONResponse(
            self._policy,
            headers={"Cache-Control": "public, max-age=3600"},
        )
