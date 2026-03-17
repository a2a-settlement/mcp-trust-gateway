"""Federation health monitor with automatic rho decay.

Polls ``/.well-known/a2a-federation-health`` on peer exchanges and
triggers exponential rho decay on consecutive failures, with asymmetric
linear recovery.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import httpx

logger = logging.getLogger("mcp_trust_gateway.federation.health")


class PeerStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"
    MAINTENANCE = "maintenance"


@dataclass
class PeerHealthStatus:
    """Tracked health state of a federation peer."""

    peer_did: str
    health_url: str
    status: PeerStatus = PeerStatus.UNREACHABLE
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_check: Optional[datetime] = None
    last_success: Optional[datetime] = None
    rho_modifier: float = 1.0  # multiplied against base rho
    remote_status: Optional[str] = None
    uptime_90d: Optional[float] = None
    avg_latency_ms: Optional[int] = None


class FederationHealthMonitor:
    """Monitors federated peer health and adjusts rho accordingly.

    Parameters
    ----------
    check_interval_seconds:
        How often to poll peer health endpoints (default: 300 = 5 min).
    decay_trigger_failures:
        Consecutive failures before rho decay starts (default: 3).
    decay_rate:
        Multiplicative decay per missed interval (default: 0.9).
    recovery_increment:
        Linear rho recovery per successful check (default: 0.02).
    quarantine_floor:
        Minimum rho_modifier before quarantine (default: 0.0).
    """

    def __init__(
        self,
        check_interval_seconds: int = 300,
        decay_trigger_failures: int = 3,
        decay_rate: float = 0.9,
        recovery_increment: float = 0.02,
        quarantine_floor: float = 0.0,
    ):
        self.check_interval = check_interval_seconds
        self.decay_trigger = decay_trigger_failures
        self.decay_rate = decay_rate
        self.recovery_increment = recovery_increment
        self.quarantine_floor = quarantine_floor
        self._peers: dict[str, PeerHealthStatus] = {}
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def add_peer(self, peer_did: str, health_url: str) -> None:
        """Register a peer for health monitoring."""
        self._peers[peer_did] = PeerHealthStatus(
            peer_did=peer_did,
            health_url=health_url,
        )

    def remove_peer(self, peer_did: str) -> None:
        self._peers.pop(peer_did, None)

    def get_peer_status(self, peer_did: str) -> Optional[PeerHealthStatus]:
        return self._peers.get(peer_did)

    def get_rho_modifier(self, peer_did: str) -> float:
        """Get the health-based rho modifier for a peer (0.0–1.0)."""
        peer = self._peers.get(peer_did)
        if peer is None:
            return 1.0
        return peer.rho_modifier

    def all_peers(self) -> list[PeerHealthStatus]:
        return list(self._peers.values())

    async def check_peer(self, peer_did: str) -> PeerHealthStatus:
        """Perform a single health check on a peer."""
        peer = self._peers.get(peer_did)
        if peer is None:
            raise ValueError(f"Unknown peer: {peer_did}")

        now = datetime.now(timezone.utc)
        peer.last_check = now

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(peer.health_url)
                resp.raise_for_status()
                data = resp.json()

            peer.remote_status = data.get("status", "unknown")
            peer.uptime_90d = data.get("uptime_90d")
            peer.avg_latency_ms = data.get("avg_attestation_latency_ms")

            if peer.remote_status == "maintenance":
                peer.status = PeerStatus.MAINTENANCE
                # Pause decay during announced maintenance
            elif peer.remote_status == "degraded":
                peer.status = PeerStatus.DEGRADED
                peer.consecutive_failures = 0
                peer.consecutive_successes += 1
                self._apply_recovery(peer)
            else:
                peer.status = PeerStatus.HEALTHY
                peer.consecutive_failures = 0
                peer.consecutive_successes += 1
                peer.last_success = now
                self._apply_recovery(peer)

        except Exception as exc:
            logger.warning(
                "Health check failed for %s: %s", peer_did, exc
            )
            peer.status = PeerStatus.UNREACHABLE
            peer.consecutive_failures += 1
            peer.consecutive_successes = 0
            self._apply_decay(peer)

        return peer

    def _apply_decay(self, peer: PeerHealthStatus) -> None:
        """Apply exponential rho decay after consecutive failures."""
        if peer.consecutive_failures >= self.decay_trigger:
            peer.rho_modifier = max(
                peer.rho_modifier * self.decay_rate,
                self.quarantine_floor,
            )

    def _apply_recovery(self, peer: PeerHealthStatus) -> None:
        """Apply linear rho recovery after successful checks."""
        if peer.rho_modifier < 1.0:
            peer.rho_modifier = min(
                peer.rho_modifier + self.recovery_increment,
                1.0,
            )

    async def start(self) -> None:
        """Start the background health monitoring loop."""
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        """Stop the background health monitoring loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self) -> None:
        while self._running:
            for peer_did in list(self._peers.keys()):
                try:
                    await self.check_peer(peer_did)
                except Exception as exc:
                    logger.error(
                        "Error checking peer %s: %s", peer_did, exc
                    )
            await asyncio.sleep(self.check_interval)
