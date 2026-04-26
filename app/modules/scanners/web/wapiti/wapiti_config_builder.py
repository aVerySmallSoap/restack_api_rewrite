from app.modules.scanners.web.wapiti.wapiti_types import WapitiFlagDefinition, WapitiConfig
from app.modules.scanners.web.wapiti.wapiti_enums import WapitiHeadlessValues
from app.modules.interfaces.enums.scanners import IConfigBuilder

# This should help the code map the correct command to the value
COMMAND_MAPPING: dict[str, WapitiFlagDefinition] = {
    "scope": WapitiFlagDefinition("--scope", True),
    "modules": WapitiFlagDefinition("-m", True),
    "level": WapitiFlagDefinition("--level", True),
    "flush_attacks": WapitiFlagDefinition("--flush-attacks", False),
    "flush_session": WapitiFlagDefinition("--flush-session", False),
    "depth": WapitiFlagDefinition("--depth", True),
    "max_scan_time": WapitiFlagDefinition("--max-scan-time", True),
    "max_attack_time": WapitiFlagDefinition("--max-attack-time", True),
    "force": WapitiFlagDefinition("--scan-force", True),
    "tasks": WapitiFlagDefinition("--tasks", True),
    "timeout": WapitiFlagDefinition("--timeout", True),
    "verify_ssl": WapitiFlagDefinition("--verify-ssl", True),
    "colored": WapitiFlagDefinition("--color", False),
    "verbose": WapitiFlagDefinition("--verbose", True),
    "format": WapitiFlagDefinition("--format", True),
    "output": WapitiFlagDefinition("--output", True),
    "detailed_report": WapitiFlagDefinition("--detailed-report", True),
    "tor": WapitiFlagDefinition("--tor", False),
    "mitm_port": WapitiFlagDefinition("--mitm-port", True),
    "headless": WapitiFlagDefinition("--headless", True),
    "wait": WapitiFlagDefinition("--wait", True),
    "auth_user": WapitiFlagDefinition("--auth-user", True),
    "auth_password": WapitiFlagDefinition("--auth-password", True),
    "auth_method": WapitiFlagDefinition("--auth-method", True),
    "form_user": WapitiFlagDefinition("--form-user", True),
    "form_password": WapitiFlagDefinition("--form-password", True),
    "form_url": WapitiFlagDefinition("--form-url", True),
    "form_data": WapitiFlagDefinition("--form-data", True),
    "form_enctype": WapitiFlagDefinition("--form-enctype", True),
    "form_script": WapitiFlagDefinition("--form-script", True),
    "cookie_file": WapitiFlagDefinition("--cookie", True),
    "side_file": WapitiFlagDefinition("--side-file", True),
    "cookie": WapitiFlagDefinition("--cookie-value", True),
    "drop_set_cookie": WapitiFlagDefinition("--drop-set-cookie", True),
    "start": WapitiFlagDefinition("--start", True),
    "exclude": WapitiFlagDefinition("--exclude", True),
    "remove": WapitiFlagDefinition("--remove", True),
    "skip": WapitiFlagDefinition("--skip", True),
    "max_links_per_page": WapitiFlagDefinition("--max-links-per-page", True),
    "max_files_per_dir": WapitiFlagDefinition("--max-files-per-dir", True),
    "max_parameters": WapitiFlagDefinition("--max-parameters", True),
    "external_endpoint": WapitiFlagDefinition("--external-endpoint", True),
    "internal_endpoint": WapitiFlagDefinition("--internal-endpoint", True),
    "endpoint": WapitiFlagDefinition("--endpoint", True),
    "dns_endpoint": WapitiFlagDefinition("--dns-endpoint", True),
    "header": WapitiFlagDefinition("--header", True),
    "agent": WapitiFlagDefinition("--user-agent", True),
    "log": WapitiFlagDefinition("--log", True),
}

class WapitiConfigBuilder(IConfigBuilder):
    """Builds the configuration for Wapiti."""
    _config: WapitiConfig # This is injected
    _url: str

    def __init__(self, config: WapitiConfig):
        self._config = config

    def url(self, url: str):
        self._url = url
        return self

    def output(self, path: str):
        self._config.output = path
        return self

    def build(self) -> list:
        command = ["wapiti", "-u", self._url]

        for field_name, value in self._config.model_dump().items():
            if field_name == "is_headless" and value:
                    self._config.headless = WapitiHeadlessValues.HIDDEN

            if value is None:
                continue
            flag_def = COMMAND_MAPPING.get(field_name)
            if flag_def is None:
                continue
            if flag_def.takes_value:
                command.extend([flag_def.flag, str(value)])
            else:
                if value:  # only append boolean flags when True
                    command.append(flag_def.flag)
        print(command)
        return command