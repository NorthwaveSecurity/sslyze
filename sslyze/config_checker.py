import pydantic
from typing import Optional, Set, Dict
from sslyze import ScanCommand


class CiphersAsJson(pydantic.BaseModel):
    caddy: Set[str]
    go: Set[str]
    iana: Set[str]
    openssl: Set[str]


class TlsConfigurationAsJson(pydantic.BaseModel):
    certificate_curves: Set[str]
    certificate_signatures: Set[str]
    certificate_types: Set[str]
    ciphersuites: Set[str]
    ciphers: CiphersAsJson
    dh_param_size: Optional[int]
    ecdh_param_size: int
    hsts_min_age: int
    maximum_certificate_lifespan: int
    ocsp_staple: bool
    recommended_certificate_lifespan: int
    rsa_key_size: Optional[int]
    server_preferred_order: bool
    tls_curves: Set[str]
    tls_versions: Set[str]


class ServerScanResultIncomplete(Exception):
    """The server scan result does not have enough information to check it against the configuration.
    """


SCAN_COMMANDS_NEEDED_BY_CHECKER: Set[ScanCommand] = {
    ScanCommand.SSL_2_0_CIPHER_SUITES,
    ScanCommand.SSL_3_0_CIPHER_SUITES,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.HEARTBLEED,
    ScanCommand.ROBOT,
    ScanCommand.OPENSSL_CCS_INJECTION,
    ScanCommand.TLS_COMPRESSION,
    ScanCommand.SESSION_RENEGOTIATION,
    ScanCommand.CERTIFICATE_INFO,
    ScanCommand.ELLIPTIC_CURVES,
}


class ServerNotCompliantWithTlsConfiguration(Exception):
    def __init__(
        self, config, issues: Dict[str, str],
    ):
        self.config = config
        self.issues = issues


