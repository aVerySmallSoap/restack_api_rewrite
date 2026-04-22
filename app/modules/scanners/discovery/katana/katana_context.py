from typing import Optional

class KatanaContext:
    """ This is the context needed for Katana."""
    primary_host: Optional[str] = None
    headless_chrome_binary: str = "/usr/bin/chromium"