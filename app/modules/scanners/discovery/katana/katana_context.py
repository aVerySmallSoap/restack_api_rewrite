from typing import Optional

from app.modules.interfaces.options import ContentableContext


class KatanaContext(ContentableContext):
    """ This is the context needed for Katana."""
    is_two_pass: bool = False
    primary_host: Optional[str] = None
    headless_chrome_binary: str = "/usr/bin/chromium"