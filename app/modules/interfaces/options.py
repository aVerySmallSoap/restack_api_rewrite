from typing import Optional

from pydantic import BaseModel

class BaseContext(BaseModel):
    # Each scanner shall contain a context that holds its own scan data
    # These contexts can be passed to context discovery to be parsed
    session_id: Optional[str] = None

    def to_json(self) -> str:
        return self.model_dump_json()

    def to_dict(self, ctx: str):
        return self.model_validate_json(ctx)

class ContentableContext(BaseContext):
    content: Optional[dict] = None

# Discovery options/contexts

class SubfinderContext(ContentableContext):
    pass

class HttpxContext(ContentableContext):
    pass

class SSLyzeContext(ContentableContext):
    pass

class WappalyzerContext(ContentableContext):
    pass

class WhatWebContext(ContentableContext):
    pass

