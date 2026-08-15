"""Abstract interface for future external sandbox communication.

Phase 7.0 does not implement a concrete sandbox controller.
All behavior analysis runs via SyntheticBehaviorAnalyzer.

Future real-sandbox implementations must:
- Submit samples by storage reference, never by embedding binary data.
- Communicate with a disposable, isolated sandbox environment.
- Never execute samples inside the API process.
- Retrieve structured JSON telemetry validated against BehaviorAnalysisResult.
- Clean up staging data after analysis completes or times out.

Preferred future isolation target: microVM / Firecracker-style architecture.
The queue boundary remains an interface; no production queue backend is assumed here.
"""

from abc import ABC, abstractmethod

from igris.schemas.behavior_analysis import (
    ArtifactRetentionPolicy,
    BehaviorAnalysisResult,
    SandboxResourceLimits,
)


class SandboxController(ABC):
    """Interface for submitting samples to an external isolated sandbox.

    Concrete implementations must run analysis in an isolated, disposable
    environment that has no access to application secrets, the database,
    or the production network.

    The API process must NEVER execute uploaded samples directly.
    """

    @abstractmethod
    async def submit(
        self,
        *,
        sample_id: str,
        storage_ref: str,
        timeout_seconds: int,
        network_policy: str,
        resource_limits: SandboxResourceLimits,
        artifact_policy: ArtifactRetentionPolicy,
    ) -> BehaviorAnalysisResult:
        """Submit a sample reference to the isolated sandbox and retrieve results.

        Args:
            sample_id: The canonical sample identifier.
            storage_ref: The binary storage reference (not a raw file path).
            timeout_seconds: Maximum execution time in the sandbox.
            network_policy: Network policy for the sandbox (e.g., "deny_all").
            resource_limits: CPU, memory, disk, process, and timeout constraints.
            artifact_policy: Bounded artifact-retention requirements.

        Returns:
            Validated behavior analysis result from the sandbox.
        """
