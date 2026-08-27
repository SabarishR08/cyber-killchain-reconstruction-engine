# killchain/stages.py
from enum import Enum


class KillChainStage(Enum):
    """Lockheed Martin 7-stage kill chain."""
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_CONTROL = "Command & Control"
    ACTIONS_ON_OBJECTIVES = "Actions on Objectives"


# Map attack patterns to kill chain stages
KILL_CHAIN_MAPPING = {
    "Brute Force Authentication Attempt": KillChainStage.EXPLOITATION,
    "Possible Credential Compromise": KillChainStage.EXPLOITATION,
    "Lateral Movement": KillChainStage.EXPLOITATION,
    "Data Exfiltration": KillChainStage.ACTIONS_ON_OBJECTIVES,
    # ── Network-Traffic-Specific Mappings (SIH26153) ──
    "Port Scan to Exploit Attempt": KillChainStage.EXPLOITATION,
    "DoS Traffic Spike": KillChainStage.ACTIONS_ON_OBJECTIVES,
}
