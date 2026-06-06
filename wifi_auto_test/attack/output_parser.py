import re
from enum import Enum


class HcxdumpStatus(Enum):
    PMKID_FOUND = "pmkid"
    M1M2_FOUND = "m1m2"
    M1M4_FOUND = "m1m4"
    ACTIVITY = "activity"
    NO_RESULT = "none"


class HcxdumpOutputParser:
    _PMKID_PATTERN = re.compile(r"M1M2E2", re.IGNORECASE)
    _M1M2_PATTERN = re.compile(r"\b(?:M1M2ROGUE|M1M2|M12ROGUE|M12)\b", re.IGNORECASE)
    _M1M4_PATTERN = re.compile(r"M1M4", re.IGNORECASE)

    def parse(self, line: str) -> HcxdumpStatus:
        line = line.strip()
        if self._PMKID_PATTERN.search(line):
            return HcxdumpStatus.PMKID_FOUND
        if self._M1M4_PATTERN.search(line):
            return HcxdumpStatus.M1M4_FOUND
        if self._M1M2_PATTERN.search(line):
            return HcxdumpStatus.M1M2_FOUND
        return HcxdumpStatus.NO_RESULT
