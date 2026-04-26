from datetime import datetime
from typing import Optional, Any, Literal
from pydantic import BaseModel


class BaseContext(BaseModel):
    """
    The base context model.

    The class itself does not follow any strict structure. However, project itself will assume that each context
    must contain a data field.
    """
    data: Optional[Any] = None

class PhaseContext(BaseModel):
    """
    Contexts that rely on a previous state.

    The class itself does not follow any strict structure. However, project itself will assume that each context
    must contain a previous context that inherits from BaseContext.
    """
    previous_context: BaseContext

class ScannerTaskResult(BaseModel):
    scanner: str
    phase: str
    status: Literal["success", "failed", "timeout", "cancelled"]

    result: Optional[dict | str] = None # This could also be a serialized
    error: Optional[str] = None

    runtime_ms: Optional[float] = None
    stdout: Optional[str | list] = None
    stderr: Optional[str | list] = None

    artifacts: list[str] = []
    exit_code: Optional[int] = None

    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

