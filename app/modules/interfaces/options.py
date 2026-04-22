from typing import Optional

from pydantic import BaseModel

class PhaseContext(BaseModel):
    """Every scanner that relies on a previous phase shall derive from this class"""
    def to_json(self) -> str:
        return self.model_dump_json()

    def to_dict(self, ctx: str):
        return self.model_validate_json(ctx)


class BaseContext(BaseModel):
    # Each scanner shall contain a context that holds its own scan data
    # These contexts can be passed to context discovery to be parsed

    def to_json(self) -> str:
        return self.model_dump_json()

    def to_dict(self, ctx: str):
        return self.model_validate_json(ctx)

