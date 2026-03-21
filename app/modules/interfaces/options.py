from abc import ABC, abstractmethod
from typing import Optional

from pydantic import BaseModel


class BaseContext(ABC, BaseModel):
    # Each scanner shall contain a context that holds its own scan data
    # These contexts can be passed to context discovery to be parsed

    @property
    @abstractmethod
    def session_id(self) -> str:
        pass

    @property
    @abstractmethod
    def content(self) -> dict:
        pass

    @session_id.setter
    def session_id(self, value):
        self._session_id = value

    @content.setter
    def content(self, value):
        self._content = value


    def to_json(self) -> str:
        import json
        return json.dumps(self, default=lambda o: o.__dict__)

class HttpxContext(BaseContext):
    session_id: str = None
    content: dict = None

class KatanaContext(BaseContext):
    """ This is the context needed for Katana."""

    @property
    def session_id(self) -> str:
        return ""

    @property
    def content(self) -> dict:
        return {}

    @session_id.setter
    def session_id(self, value):
        self.session_id = value

    @content.setter
    def content(self, value):
        self.content = value

    is_two_pass: bool = False
    primary_host: Optional[str] = None
    headless_chrome_binary: str = "/usr/bin/chromium"

class SSLyzeContext(BaseContext):
    session_id:str = None
    content: dict = None

class SubfinderContext(BaseContext):
    @property
    def session_id(self) -> str:
        return ""

    @property
    def content(self) -> dict:
        return {}

    @session_id.setter
    def session_id(self, value):
        self.session_id = value

    @content.setter
    def content(self, value):
        self.content = value

class WappalyzerContext(BaseContext):
    session_id:str = None
    content: dict = None

class WhatWebContext(BaseContext):
    session_id:str = None
    content: dict = None