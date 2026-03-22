from abc import ABC, abstractmethod
from typing import Optional

from pydantic import BaseModel


class BaseContext(BaseModel):
    # Each scanner shall contain a context that holds its own scan data
    # These contexts can be passed to context discovery to be parsed
    session_id: str = None
    content: dict = None

    def to_json(self) -> str:
        return self.model_dump_json()

    def to_dict(self, ctx: str):
        return self.model_validate_json(ctx)


class SubfinderContext(BaseContext):
    pass

class KatanaContext(BaseContext):
    """ This is the context needed for Katana."""
    is_two_pass: bool = False
    primary_host: Optional[str] = None
    headless_chrome_binary: str = "/usr/bin/chromium"

class HttpxContext(BaseContext):
    pass

class SSLyzeContext(BaseContext):
    pass

class WappalyzerContext(BaseContext):
    pass

class WhatWebContext(BaseContext):
    pass