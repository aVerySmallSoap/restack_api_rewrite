from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel

from app.modules.interfaces.enums.wapiti.wapiti_enums import WapitiAuthMethodValues, WapitiHeadlessValues, \
    WapitiVerifySSLValues, WapitiScanForceValues, WapitiModulesValues, WapitiScopeValues


class WapitiConfig(BaseModel):
    scope: WapitiScopeValues                                        = WapitiScopeValues.DOMAIN
    modules: WapitiModulesValues | list[WapitiModulesValues]        = WapitiModulesValues.COMMON
    level: int                                                      = 1 # 1 or 2
    flush_attacks: bool                                             = True
    flush_session: bool                                             = True
    depth: int                                                      = -1
    max_scan_time: int                                              = 180
    max_attack_time: int                                            = 280
    force: WapitiScanForceValues                                    = WapitiScanForceValues.SNEAKY
    tasks: int                                                      = 4
    timeout: int                                                    = 15
    verify_ssl: WapitiVerifySSLValues                               = WapitiVerifySSLValues.YES
    colored: bool                                                   = False
    verbose: bool                                                   = True
    format: str                                                     = "json"
    output: str                                                     = None
    detailed_report: int                                            = 1

    # mostly important optionals
    tor: Optional[bool]                                             = False
    mitm_port: Optional[int]                                        = 80
    headless: Optional[WapitiHeadlessValues]                        = WapitiHeadlessValues.HIDDEN
    wait: Optional[int]                                             = 10

    # optionals

    # auth
    auth_user: Optional[str]                                        = None
    auth_password: Optional[str]                                    = None
    auth_method: Optional[WapitiAuthMethodValues]                   = None
    form_user: Optional[str]                                        = None
    form_password: Optional[str]                                    = None
    form_url: Optional[str]                                         = None
    form_data: Optional[str]                                        = None #should accept as dict then resolved to a str
    form_enctype: Optional[str]                                     = None
    form_script: Optional[str]                                      = None # should be checked since this could invoke some nasty code injection stuff
    cookie_file: Optional[str]                                      = None # path
    side_file: Optional[str]                                        = None # path
    cookie: Optional[str]                                           = None # should accept dict then resolved to a string
    drop_set_cookie: Optional[bool]                                 = None

    # scanner control !NOT USED!
    skip_crawl: Optional[bool]                                      = None
    resume_crawl: Optional[bool]                                    = None
    store_session: Optional[str]                                    = None # path
    store_config: Optional[str]                                     = None # path

    # URL control
    start: Optional[str]                                            = None # URL
    exclude: Optional[str]                                          = None # URL
    remove: Optional[str]                                           = None # See -r
    skip: Optional[str]                                             = None # See --skip
    max_links_per_page: Optional[int]                               = None
    max_files_per_dir: Optional[int]                                = None
    max_parameters: Optional[int]                                   = None
    external_endpoint: Optional[str]                                = None
    internal_endpoint: Optional[str]                                = None
    endpoint: Optional[str]                                         = None
    dns_endpoint: Optional[str]                                     = None

    # Request Control
    header: Optional[str]                                           = None
    agent: Optional[str]                                            = None

    # extra
    log: Optional[str] = None # path

@dataclass
class WapitiFlagDefinition:
    flag: str
    takes_value: bool