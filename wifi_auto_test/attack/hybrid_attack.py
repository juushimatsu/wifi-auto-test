import shutil

from wifi_auto_test.core.models import WiFiNetwork, TestResult
from .interfaces import IAttackEngine


class HybridAttack(IAttackEngine):
    """Auto-selects HcxdumpAttack when hcxdumptool is available, otherwise falls back to AirodumpAttack."""

    def __init__(
        self,
        hcxdump: IAttackEngine,
        airodump: IAttackEngine,
    ):
        self._hcxdump = hcxdump
        self._airodump = airodump
        self._has_hcxdump = shutil.which("hcxdumptool") is not None

    def run(self, network: WiFiNetwork) -> TestResult:
        if self._has_hcxdump:
            return self._hcxdump.run(network)
        return self._airodump.run(network)

    def terminate(self) -> None:
        for attack in (self._hcxdump, self._airodump):
            terminate = getattr(attack, "terminate", None)
            if terminate:
                terminate()
