import re
from enum import Enum


class HcxdumpStatus(Enum):
    PMKID_FOUND = "pmkid"
    M1M4_FOUND = "m1m4"
    ACTIVITY = "activity"
    NO_RESULT = "none"


class HcxdumpOutputParser:
    _PMKID_PATTERN = re.compile(r"M1M2E2", re.IGNORECASE)
    _M1M4_PATTERN = re.compile(r"M1M4", re.IGNORECASE)
    _ACTIVITY_PATTERN = re.compile(r"M12ROGUE|M12", re.IGNORECASE)

    def parse(self, line: str) -> HcxdumpStatus:
        line = line.strip()
        if self._PMKID_PATTERN.search(line):
            return HcxdumpStatus.PMKID_FOUND
        if self._M1M4_PATTERN.search(line):
            return HcxdumpStatus.M1M4_FOUND
        if self._ACTIVITY_PATTERN.search(line):
            return HcxdumpStatus.ACTIVITY
        return HcxdumpStatus.NO_RESULT
