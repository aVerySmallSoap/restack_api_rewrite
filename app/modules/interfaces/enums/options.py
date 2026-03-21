from typing import Optional

from docker.models.containers import Container
from pydantic import BaseModel


class HttpxContext(BaseModel):
    session_id: str = None

class KatanaContext(BaseModel):
    """ This is the context needed for Katana."""
    session_id: str = None
    is_two_pass: bool = False
    primary_host: Optional[str] = None
    headless_chrome_binary: str = "/usr/bin/chromium"
    standard_container_name: str = None
    headless_container_name: str = None

class SSLyzeContext(BaseModel):
    session_id: str = None

class SubfinderContext(BaseModel):
    session_id: str = None

class WappalyzerContext(BaseModel):
    session_id: str = None

class WhatWebContext(BaseModel):
    session_id: str = None