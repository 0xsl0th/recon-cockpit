"""Owned TLS transport exercised through the existing networkless parser.

This adapter is intentionally separate from the offline authority and evaluation
runner. It returns an untrusted proposal and has no tool-execution interface.
"""

from .openai_isolation import LinuxOpenAIPlanner
from .provider_broker import OwnedProviderBroker
from .provider_contract import release_observation
from .provider_lab import LinuxOwnedProviderTransport


class OwnedTLSProvider:
    name = "linux-isolated-owned-tls-provider-v1"

    def __init__(self, audit, *, scenario="success", limits=None, tariff=None):
        self.broker = OwnedProviderBroker(audit, LinuxOwnedProviderTransport(scenario),
                                          limits=limits, tariff=tariff)
        self._planner = LinuxOpenAIPlanner()

    @property
    def boundary_checks(self):
        return self._planner.boundary_checks

    def propose(self, observation, *, control):
        released = release_observation(observation)
        return self._planner.plan(
            self.broker.config, released,
            lambda request, *, control: self.broker.exchange(observation, request, control=control),
            control=control,
        )
