from enum import Enum


class ScanProgress(str, Enum):
    IN_PROGRESS = 'IN_PROGRESS'
    SUCCESS = 'SUCCESS'
    ERROR = 'ERROR'
    FAILED = 'FAILED'

class ScanPhase(str, Enum):
    PREAMBLE = 'PREAMBLE'
    LIVELINESS = 'LIVELINESS'
    ASSET = 'ASSET'
    VULN_QUERY = 'VULN_QUERY'
    ATTACK = 'ATTACK'
    NORMALIZATION = 'NORMALIZATION'

class ScanTypes(str, Enum):
    FULL = 'FULL'
    QUICK = 'QUICK'
    CUSTOM = 'CUSTOM'