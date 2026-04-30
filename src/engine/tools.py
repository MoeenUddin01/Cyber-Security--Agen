"""Security response tools for automated threat mitigation."""

from __future__ import annotations

import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def block_ip_tool(ip_address: str, attack_type: str) -> str:
    """Simulate blocking an IP address by generating an iptables command.

    In a real production environment, this would execute a subprocess command.
    For the project demo, actions are logged to 'security_actions.log'.

    Args:
        ip_address: The IP address to block.
        attack_type: The type of attack detected.

    Returns:
        Confirmation message with the generated command.

    Raises:
        ValueError: If ip_address or attack_type is empty.
    """
    if not ip_address:
        raise ValueError("IP address cannot be empty")
    if not attack_type:
        raise ValueError("Attack type cannot be empty")

    command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"

    log_file = Path("security_actions.log")
    with open(log_file, "a") as f:
        f.write(f"ACTION: {attack_type} detected. Executed: {command}\n")

    logger.info(f"Generated mitigation rule for {ip_address} ({attack_type})")

    return f"Successfully generated mitigation rule: {command}"
