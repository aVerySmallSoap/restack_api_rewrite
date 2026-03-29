from enum import StrEnum, IntEnum

class WapitiScopeValues(StrEnum):
    URL = "url"
    PAGE = "page"
    FOLDER = "folder"
    SUBDOMAIN = "subdomain"
    DOMAIN = "domain"
    PUNK = "punk"

class WapitiModulesValues(StrEnum):
    BACKUP = "backup"
    BRUTE_LOGIN_FORM = "brute_login_form"
    BUSTER = "buster"
    CMS = "cms"
    CRLF = "crlf"
    CSRF = "csrf"
    EXEC = "exec"
    FILE = "file"
    HTACCESS = "htaccess"
    HTP = "htp"
    LDAP = "ldap"
    LOG4SHELL = "log4shell"
    METHODS = "methods"
    NETWORK_DEVICE = "network_device"
    NIKTO = "nikto"
    PERMANENT_XSS = "permanentxss"
    REDIRECT = "redirect"
    SHELLSHOCK = "shellshock"
    SPRING4SHELL = "spring4shell"
    SQL = "sql"
    SSL = "ssl"
    SSRF = "ssrf"
    TAKEOVER = "takeover"
    TIMESQL = "timesql"
    UPLOAD = "upload"
    WAPP = "wapp"
    WP_ENUM = "wp_enum"
    XSS = "xss"
    XXE = "xxe"
    COMMON = "common"
    ALL = "all"
    EMPTY = ""

class WapitiHeadlessValues(StrEnum):
    NO = "no"
    HIDDEN = "hidden"
    VISIBLE = "visible"

class WapitiAuthMethodValues(StrEnum):
    BASIC = "basic"
    DIGEST = "digest"
    NTLM = "ntlm"

class WapitiScanForceValues(StrEnum):
    PARANOID = "paranoid"
    SNEAKY = "sneaky"
    POLITE = "polite"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"
    INSANE = "insane"

class WapitiVerifySSLValues(IntEnum):
    NO = 0
    YES = 1