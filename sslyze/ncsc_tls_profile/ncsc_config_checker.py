import json
from enum import Enum
from pathlib import Path
from typing import Optional, Set, Dict

import pydantic
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from nassl.ephemeral_key_info import EcDhEphemeralKeyInfo, DhEphemeralKeyInfo

from sslyze import (
    ServerScanResult,
    ServerScanStatusEnum,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    CertificateInfoScanResult,
    AllScanCommandsAttempts,
    CipherSuitesScanResult,
    RobotScanResultEnum,
    SupportedEllipticCurvesScanResult,
)

from sslyze.config_checker import (
    CiphersAsJson,
    TlsConfigurationAsJson,
    ServerScanResultIncomplete,
    SCAN_COMMANDS_NEEDED_BY_CHECKER,
    ServerNotCompliantWithTlsConfiguration,
)

from sslyze.mozilla_tls_profile.mozilla_config_checker import (
    TlsConfigurationChecker
)

class _AllTlsConfigurationsAsJson(pydantic.BaseModel):
    modern: TlsConfigurationAsJson
    intermediate: TlsConfigurationAsJson
    old: TlsConfigurationAsJson


class TlsProfileAsJson(pydantic.BaseModel):
    version: str
    href: str
    configurations: _AllTlsConfigurationsAsJson


class TlsConfigurationEnum(str, Enum):
    MODERN = "modern"
    INTERMEDIATE = "intermediate"
    OLD = "old"


class NCSCServerScanResultIncomplete(ServerScanResultIncomplete):
    """The server scan result does not have enough information to check it against NCSC's configuration.
    """

class TlsConfigurationChecker(TlsConfigurationChecker):
    version = "1.0"

    def __init__(self, tls_profile: TlsProfileAsJson):
        self._tls_profile = tls_profile

    @classmethod
    def get_default(cls) -> "TlsConfigurationChecker":
        json_profile_path = Path(__file__).parent.absolute() / (cls.version + ".json")
        json_profile_as_str = json_profile_path.read_text()
        parsed_profile = TlsProfileAsJson(**json.loads(json_profile_as_str))
        return cls(parsed_profile)

    def check_server(self, against_config: TlsConfigurationEnum, server_scan_result: ServerScanResult,) -> None:
        # Ensure the scan was successful
        if server_scan_result.scan_status != ServerScanStatusEnum.COMPLETED:
            raise ServerScanResultIncomplete("The server scan was not completed.")

        # Ensure all the scan command we need were run successfully
        for scan_command in SCAN_COMMANDS_NEEDED_BY_CHECKER:
            scan_cmd_attempt = getattr(server_scan_result.scan_result, scan_command.value)
            if scan_cmd_attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
                raise ServerScanResultIncomplete(f"The {scan_command.value} result is missing.")

        # Now let's check the server's scan results against the NCSC config
        config: TlsConfigurationAsJson = getattr(
            self._tls_profile.configurations, against_config.value
        )
        all_issues: Dict[str, str] = {}

        # Checks on the certificate
        assert server_scan_result.scan_result
        assert server_scan_result.scan_result.certificate_info
        assert server_scan_result.scan_result.certificate_info.result
        issues_with_certificates = _check_certificates(
            cert_info_result=server_scan_result.scan_result.certificate_info.result, config=config,
        )
        all_issues.update(issues_with_certificates)

        # Checks on the TLS versions and cipher suites
        assert server_scan_result.scan_result
        issues_with_tls_ciphers = _check_tls_versions_and_ciphers(server_scan_result.scan_result, config)
        all_issues.update(issues_with_tls_ciphers)

        # Checks on the TLS curves
        assert server_scan_result.scan_result.elliptic_curves.result
        issues_with_tls_curves = _check_tls_curves(
            server_scan_result.scan_result.elliptic_curves.result, config,
        )
        all_issues.update(issues_with_tls_curves)

        # Checks on TLS vulnerabilities
        issues_with_tls_vulns = _check_tls_vulnerabilities(server_scan_result.scan_result)
        all_issues.update(issues_with_tls_vulns)

        if all_issues:
            raise ServerNotCompliantWithTlsConfiguration(
                config=against_config, issues=all_issues,
            )


def _check_tls_curves(
    tls_curves_result: SupportedEllipticCurvesScanResult, config: TlsConfigurationAsJson,
) -> Dict[str, str]:
    issues_with_tls_curves = {}
    if tls_curves_result.supported_curves:
        supported_curves = {curve.name for curve in tls_curves_result.supported_curves}
    else:
        supported_curves = set()

    tls_curves_difference = supported_curves - config.tls_curves
    if tls_curves_difference:
        issues_with_tls_curves[
            "tls_curves"
        ] = f"TLS curves {tls_curves_difference} are supported, but should be rejected."

    # TODO(AD): Disable the check on the curves; not even Google, NCSC nor Cloudflare are compliant...
    # return problems_with_tls_curves
    return {}


def _check_tls_vulnerabilities(scan_result: AllScanCommandsAttempts) -> Dict[str, str]:
    issues_with_tls_vulns = {}
    assert scan_result.tls_compression.result
    if scan_result.tls_compression.result.supports_compression:
        issues_with_tls_vulns["tls_vulnerability_compression"] = "Server is vulnerable to TLS compression attacks."

    assert scan_result.openssl_ccs_injection.result
    if scan_result.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection:
        issues_with_tls_vulns[
            "tls_vulnerability_ccs_injection"
        ] = "Server is vulnerable to the OpenSSL CCS injection attack."

    assert scan_result.heartbleed.result
    if scan_result.heartbleed.result.is_vulnerable_to_heartbleed:
        issues_with_tls_vulns["tls_vulnerability_heartbleed"] = "Server is vulnerable to the OpenSSL Heartbleed attack."

    assert scan_result.robot.result
    if scan_result.robot.result.robot_result == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE:
        issues_with_tls_vulns["tls_vulnerability_robot"] = "Server is vulnerable to the ROBOT attack."

    assert scan_result.session_renegotiation.result
    if not scan_result.session_renegotiation.result.supports_secure_renegotiation:
        issues_with_tls_vulns[
            "tls_vulnerability_renegotiation"
        ] = "Server is vulnerable to the insecure renegotiation attack."

    return issues_with_tls_vulns


def _check_tls_versions_and_ciphers(
    scan_result: AllScanCommandsAttempts, config: TlsConfigurationAsJson,
) -> Dict[str, str]:
    # First parse the results related to TLS versions and ciphers
    tls_versions_supported = set()
    cipher_suites_supported = set()
    tls_1_3_cipher_suites_supported = set()
    curves_supported = set()
    smallest_ecdh_param_size = 100000
    smallest_dh_param_size = 100000
    for field_name, tls_version_name in [
        ("ssl_2_0_cipher_suites", "SSLv2"),
        ("ssl_3_0_cipher_suites", "SSLv3"),
        ("tls_1_0_cipher_suites", "TLSv1"),
        ("tls_1_1_cipher_suites", "TLSv1.1"),
        ("tls_1_2_cipher_suites", "TLSv1.2"),
        ("tls_1_3_cipher_suites", "TLSv1.3"),
    ]:
        tls_scan_result: CipherSuitesScanResult = getattr(scan_result, field_name).result
        if tls_scan_result.is_tls_version_supported:
            tls_versions_supported.add(tls_version_name)
            for accepted_cipher_suite in tls_scan_result.accepted_cipher_suites:
                if tls_version_name == "TLSv1.3":
                    tls_1_3_cipher_suites_supported.add(accepted_cipher_suite.cipher_suite.name)
                else:
                    cipher_suites_supported.add(accepted_cipher_suite.cipher_suite.name)

                ephemeral_key = accepted_cipher_suite.ephemeral_key
                if isinstance(ephemeral_key, EcDhEphemeralKeyInfo):
                    curves_supported.add(ephemeral_key.curve_name)
                    actual_key_size = ephemeral_key.size + 3  # OpenSSL returns 253 instead of 255 for the secret key
                    smallest_ecdh_param_size = min([smallest_ecdh_param_size, actual_key_size])

                elif isinstance(ephemeral_key, DhEphemeralKeyInfo):
                    smallest_dh_param_size = min([smallest_dh_param_size, ephemeral_key.size])

    # Then check the results
    issues_with_tls_ciphers = {}
    tls_versions_difference = tls_versions_supported - config.tls_versions
    if tls_versions_difference:
        issues_with_tls_ciphers[
            "tls_versions"
        ] = f"TLS versions {tls_versions_difference} are supported, but should be rejected."

    tls_1_3_cipher_suites_difference = tls_1_3_cipher_suites_supported - config.ciphersuites
    if tls_1_3_cipher_suites_difference:
        issues_with_tls_ciphers[
            "ciphersuites"
        ] = f"TLS 1.3 cipher suites {tls_1_3_cipher_suites_difference} are supported, but should be rejected."

    cipher_suites_difference = cipher_suites_supported - config.ciphers.iana
    if cipher_suites_difference:
        issues_with_tls_ciphers[
            "ciphers"
        ] = f"Cipher suites {cipher_suites_difference} are supported, but should be rejected."

    if config.ecdh_param_size and smallest_ecdh_param_size < config.ecdh_param_size:
        issues_with_tls_ciphers["ecdh_param_size"] = (
            f"ECDH parameter size is {smallest_ecdh_param_size},"
            f" should be superior or equal to {config.ecdh_param_size}."
        )

    if config.dh_param_size and smallest_dh_param_size < config.dh_param_size:
        issues_with_tls_ciphers["dh_param_size"] = (
            f"DH parameter size is {smallest_dh_param_size},"
            f" should be superior or equal to {config.dh_param_size}."
        )

    return issues_with_tls_ciphers


def _check_certificates(
    cert_info_result: CertificateInfoScanResult, config: TlsConfigurationAsJson,
) -> Dict[str, str]:
    issues_with_certificates = {}
    deployed_key_algorithms = set()
    deployed_signature_algorithms = set()
    for cert_deployment in cert_info_result.certificate_deployments:
        # Validate certificate trust
        leaf_cert = cert_deployment.received_certificate_chain[0]
        if not cert_deployment.leaf_certificate_subject_matches_hostname:
            issues_with_certificates[
                "certificate_hostname_validation"
            ] = f"Certificate hostname validation failed for {leaf_cert.subject.rfc4514_string()}."
        if not cert_deployment.verified_certificate_chain:
            issues_with_certificates[
                "certificate_path_validation"
            ] = f"Certificate not path validation failed for {leaf_cert.subject.rfc4514_string()}."

        # Validate the public key
        public_key = leaf_cert.public_key()
        if isinstance(public_key, EllipticCurvePublicKey):
            deployed_key_algorithms.add("ecdsa")
            if public_key.curve.name not in config.certificate_curves:
                # TODO(AD): Disable the check on the curves; not even Google and Cloudflare are compliant...
                pass
                # problems_with_certificates["certificate_curves"] = (
                #     f"Certificate curve is {public_key.curve.name},"
                #     f" should be one of {expected_config.certificate_curves}."
                # )

        elif isinstance(public_key, RSAPublicKey):
            deployed_key_algorithms.add("rsa")
            if config.rsa_key_size and public_key.key_size < config.rsa_key_size:
                issues_with_certificates[
                    "rsa_key_size"
                ] = f"RSA key size is {public_key.key_size}, minimum allowed is {config.rsa_key_size}."

        else:
            deployed_key_algorithms.add(public_key.__class__.__name__)

        deployed_signature_algorithms.add(leaf_cert.signature_algorithm_oid._name)

        # Validate the cert's lifespan
        leaf_cert_lifespan = leaf_cert.not_valid_after - leaf_cert.not_valid_before
        if leaf_cert_lifespan.days > config.maximum_certificate_lifespan:
            issues_with_certificates["maximum_certificate_lifespan"] = (
                f"Certificate life span is {leaf_cert_lifespan.days} days,"
                f" should be less than {config.maximum_certificate_lifespan}."
            )

    # TODO(AD): It's unclear whether the NCSC profile/configs takes into accounts servers with multiple leaf certs
    #  What follows is my personal guess as to how it should work for multi-certs deployments...

    # Validate the public key algorithms
    # At least one of the NCSC cert types should have been detected in the server's cert deployments
    found_cert_type = False
    for key_algorithm in config.certificate_types:
        if key_algorithm in deployed_key_algorithms:
            found_cert_type = True
            break
    if not found_cert_type:
        issues_with_certificates["certificate_types"] = (
            f"Deployed certificate types are {deployed_key_algorithms},"
            f" should have at least one of {config.certificate_types}."
        )

    # Validate the signature algorithms
    found_sig_algorithm = False
    for sig_algorithm in config.certificate_signatures:
        if sig_algorithm in deployed_signature_algorithms:
            found_sig_algorithm = True
            break
    if not found_sig_algorithm:
        issues_with_certificates["certificate_signatures"] = (
            f"Deployed certificate signatures are {deployed_signature_algorithms},"
            f" should have at least one of {config.certificate_signatures}."
        )

    return issues_with_certificates
