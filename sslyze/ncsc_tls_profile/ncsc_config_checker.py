from pathlib import Path
import pydantic
from enum import Enum
from typing import Optional, Set, Dict
from sslyze.config_checker import (
    ServerScanResultIncomplete,
    SCAN_COMMANDS_NEEDED_BY_CHECKER,
    ServerNotCompliantWithTlsConfiguration,
    TlsConfigurationChecker as BaseTlsConfigurationChecker,
    _parse_tls_and_cipher_results,
    ParsedTlsAndCipherResults,
    AllScanCommandsAttempts,
    ServerScanResult,
)

class TlsConfigurationEnum(str, Enum):
    GOOD = "good"
    SUFFICIENT = "sufficient"
    PHASE_OUT = "phase_out"


class TlsConfigurationAsJson(pydantic.BaseModel):
    certificate_curves: Set[str]
    certificate_signatures: Set[str]
    certificate_types: Set[str]
    ciphersuites: Set[str]
    ciphers: Set[str]
    dh_param_size: Optional[int]
    ecdh_param_size: int
    hsts_min_age: int
    ocsp_staple: bool
    rsa_key_size: Optional[int]
    server_preferred_order: bool
    tls_curves: Set[str]
    tls_versions: Set[str]


class _AllTlsConfigurationsAsJson(pydantic.BaseModel):
    good: TlsConfigurationAsJson
    sufficient: TlsConfigurationAsJson
    phase_out: TlsConfigurationAsJson


class TlsProfileAsJson(pydantic.BaseModel):
    version: str
    href: str
    configurations: _AllTlsConfigurationsAsJson


class TlsConfigurationChecker(BaseTlsConfigurationChecker):
    json_profile_path = Path(__file__).parent.absolute() / "1.0.json"
    TlsProfileAsJson = TlsProfileAsJson 

    def get_config_to_check_against(self, against_config):
        config = super().get_config_to_check_against(against_config)
        if against_config.value == TlsConfigurationEnum.SUFFICIENT:
            # Good ciphers are also sufficient
            config.ciphers |= self._tls_profile.configurations.good.ciphers
            config.ciphersuites |= self._tls_profile.configurations.good.ciphersuites
        if against_config.value == TlsConfigurationEnum.PHASE_OUT:
            # All ciphers should be included
            config.ciphers |= self._tls_profile.configurations.good.ciphers
            config.ciphers |= self._tls_profile.configurations.sufficient.ciphers
            config.ciphersuites |= self._tls_profile.configurations.good.ciphersuites
            config.ciphersuites |= self._tls_profile.configurations.sufficient.ciphersuites
        return config

    def check_tls_ciphers(self, server_scan_result, config, all_issues):
        # Checks on the TLS versions and cipher suites
        # First parse the results related to TLS versions and ciphers
        results = _parse_tls_and_cipher_results(server_scan_result.scan_result)
        issues_with_tls_ciphers = {}
        tls_versions_difference = results.tls_versions_supported - config.tls_versions
        if tls_versions_difference:
            issues_with_tls_ciphers[
                "tls_versions"
            ] = f"TLS versions {tls_versions_difference} are supported, but should be rejected."

        tls_1_3_cipher_suites_difference = results.tls_1_3_cipher_suites_supported - config.ciphersuites
        if tls_1_3_cipher_suites_difference:
            issues_with_tls_ciphers[
                "ciphersuites"
            ] = f"TLS 1.3 cipher suites {tls_1_3_cipher_suites_difference} are supported, but should be rejected."

        cipher_suites_difference = results.cipher_suites_supported - config.ciphers

        sufficient_ciphers = cipher_suites_difference & self._tls_profile.configurations.sufficient.ciphers
        if sufficient_ciphers:
            issues_with_tls_ciphers["sufficient_ciphers"] = f"The following sufficient ciphers are supported: {sufficient_ciphers}. These are less secure than 'good' ciphers."

        phase_out_ciphers = cipher_suites_difference & self._tls_profile.configurations.phase_out.ciphers                
        if phase_out_ciphers:
            issues_with_tls_ciphers[
                "phase_out_ciphers"
            ] = f"The following phase-out cipher suites are supported: {cipher_suites_difference}. These should be rejected."

        # Check if unclassified ciphers are found.
        unknown_ciphers = cipher_suites_difference - sufficient_ciphers - self._tls_profile.configurations.phase_out.ciphers
        if unknown_ciphers:
            issues_with_tls_ciphers["unknown_ciphers"] = f"Unknown ciphers detected: {unknown_ciphers}. These ciphers should be classified and added to the configuration"

        if config.ecdh_param_size and results.smallest_ecdh_param_size < config.ecdh_param_size:
            issues_with_tls_ciphers["ecdh_param_size"] = (
                f"ECDH parameter size is {results.smallest_ecdh_param_size},"
                f" should be superior or equal to {config.ecdh_param_size}."
            )

        if config.dh_param_size and results.smallest_dh_param_size < config.dh_param_size:
            issues_with_tls_ciphers["dh_param_size"] = (
                f"DH parameter size is {results.smallest_dh_param_size},"
                f" should be superior or equal to {config.dh_param_size}."
            )

        # Then check the results
        all_issues.update(issues_with_tls_ciphers)