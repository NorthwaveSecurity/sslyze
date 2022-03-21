from pathlib import Path
from sslyze.config_checker import (
    CiphersAsJson,
    TlsConfigurationAsJson,
    ServerScanResultIncomplete,
    SCAN_COMMANDS_NEEDED_BY_CHECKER,
    ServerNotCompliantWithTlsConfiguration,
    TlsConfigurationChecker as BaseTlsConfigurationChecker ,
    TlsConfigurationEnum,
)

class TlsConfigurationChecker(BaseTlsConfigurationChecker):
    json_profile_path = Path(__file__).parent.absolute() / "5.6.json"
