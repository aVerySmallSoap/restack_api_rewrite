from dataclasses import dataclass

from app.modules.interfaces.options import PhaseContext


@dataclass
class LivelinessContext(PhaseContext):
    pass