from app.modules.scanners.web.wapiti.wapiti_types import WapitiFlagDefinition, WapitiConfig
from app.modules.scanners.web.wapiti.wapiti_enums import WapitiHeadlessValues
from app.modules.interfaces.enums.scanners import IConfigBuilder

# This should help the code map the correct command to the value
COMMAND_MAPPING: dict[str, WapitiFlagDefinition] = {
    "scope": WapitiFlagDefinition(flag="--scope", takes_value=True),
    "modules": WapitiFlagDefinition(flag="-m", takes_value=True),
    "level": WapitiFlagDefinition(flag="--level", takes_value=True),
    "flush_attacks": WapitiFlagDefinition(flag="--flush-attacks", takes_value=False),
    "flush_session": WapitiFlagDefinition(flag="--flush-session", takes_value=False),
    "depth": WapitiFlagDefinition(flag="--depth", takes_value=True),
    "max_scan_time": WapitiFlagDefinition(flag="--max-scan-time", takes_value=True),
    "max_attack_time": WapitiFlagDefinition(flag="--max-attack-time", takes_value=True),
    "force": WapitiFlagDefinition(flag="--scan-force", takes_value=True),
    "tasks": WapitiFlagDefinition(flag="--tasks", takes_value=True),
    "timeout": WapitiFlagDefinition(flag="--timeout", takes_value=True),
    "verify_ssl": WapitiFlagDefinition(flag="--verify-ssl", takes_value=True),
    "colored": WapitiFlagDefinition(flag="--color", takes_value=False),
    "verbose": WapitiFlagDefinition(flag="--verbose", takes_value=True),
    "format": WapitiFlagDefinition(flag="--format", takes_value=True),
    "output": WapitiFlagDefinition(flag="--output", takes_value=True),
    "detailed_report": WapitiFlagDefinition(flag="--detailed-report", takes_value=True),
    "tor": WapitiFlagDefinition(flag="--tor", takes_value=False),
    "mitm_port": WapitiFlagDefinition(flag="--mitm-port", takes_value=True),
    "headless": WapitiFlagDefinition(flag="--headless", takes_value=True),
    "wait": WapitiFlagDefinition(flag="--wait", takes_value=True),
    "auth_user": WapitiFlagDefinition(flag="--auth-user", takes_value=True),
    "auth_password": WapitiFlagDefinition(flag="--auth-password", takes_value=True),
    "auth_method": WapitiFlagDefinition(flag="--auth-method", takes_value=True),
    "form_user": WapitiFlagDefinition(flag="--form-user", takes_value=True),
    "form_password": WapitiFlagDefinition(flag="--form-password", takes_value=True),
    "form_url": WapitiFlagDefinition(flag="--form-url", takes_value=True),
    "form_data": WapitiFlagDefinition(flag="--form-data", takes_value=True),
    "form_enctype": WapitiFlagDefinition(flag="--form-enctype", takes_value=True),
    "form_script": WapitiFlagDefinition(flag="--form-script", takes_value=True),
    "cookie_file": WapitiFlagDefinition(flag="--cookie", takes_value=True),
    "side_file": WapitiFlagDefinition(flag="--side-file", takes_value=True),
    "cookie": WapitiFlagDefinition(flag="--cookie-value", takes_value=True),
    "drop_set_cookie": WapitiFlagDefinition(flag="--drop-set-cookie", takes_value=True),
    "start": WapitiFlagDefinition(flag="--start", takes_value=True),
    "exclude": WapitiFlagDefinition(flag="--exclude", takes_value=True),
    "remove": WapitiFlagDefinition(flag="--remove", takes_value=True),
    "skip": WapitiFlagDefinition(flag="--skip", takes_value=True),
    "max_links_per_page": WapitiFlagDefinition(flag="--max-links-per-page", takes_value=True),
    "max_files_per_dir": WapitiFlagDefinition(flag="--max-files-per-dir", takes_value=True),
    "max_parameters": WapitiFlagDefinition(flag="--max-parameters", takes_value=True),
    "external_endpoint": WapitiFlagDefinition(flag="--external-endpoint", takes_value=True),
    "internal_endpoint": WapitiFlagDefinition(flag="--internal-endpoint", takes_value=True),
    "endpoint": WapitiFlagDefinition(flag="--endpoint", takes_value=True),
    "dns_endpoint": WapitiFlagDefinition(flag="--dns-endpoint", takes_value=True),
    "header": WapitiFlagDefinition(flag="--header", takes_value=True),
    "agent": WapitiFlagDefinition(flag="--user-agent", takes_value=True),
    "log": WapitiFlagDefinition(flag="--log", takes_value=True),
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
        return command