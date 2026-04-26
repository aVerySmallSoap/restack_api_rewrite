from enum import Enum
from typing import Optional

class ZapContext:
    config: Optional[dict] = None

class ZapScanProfiles(str, Enum):
    default     = "QA Standard Policy",
    QA          = "QA Standard Policy",
    QA_FULL     = "QA Full Policy",
    PENTEST     = "Penetration Tester Policy",
    API         = "API Policy"