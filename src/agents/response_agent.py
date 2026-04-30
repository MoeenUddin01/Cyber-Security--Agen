"""Security response agent for automated threat mitigation."""

from __future__ import annotations

from typing import Any

from src.engine.tools import block_ip_tool


class ResponseAgent:
    """Agent that generates automated responses to security threats.

    This agent analyzes model predictions and triggers appropriate
    mitigation actions for detected attacks.

    Attributes:
        prediction: The predicted attack label from the model.
        ip: The source IP address extracted from the flow data.
    """

    def __init__(self, model_output: dict[str, Any]) -> None:
        """Initialize the ResponseAgent with model predictions.

        Args:
            model_output: Dictionary containing 'label' (prediction) and
                'source_ip' (IP address from flow data).

        Raises:
            KeyError: If required keys are missing from model_output.
        """
        self.prediction: str = model_output["label"]
        self.ip: str = model_output["source_ip"]

    def generate_response(self) -> dict[str, str]:
        """Generate and execute security response based on prediction.

        If the prediction is not BENIGN (i.e., an attack is detected),
        the agent triggers IP blocking via the block_ip_tool.

        Returns:
            Dictionary containing response status, action details, and summary.
        """
        if self.prediction != "BENIGN":
            result = block_ip_tool(self.ip, self.prediction)
            summary = (
                f"Security Alert: {self.prediction} attack neutralized. "
                f"Blocked IP {self.ip} to protect the network."
            )
            return {
                "status": "Mitigated",
                "action": result,
                "summary": summary,
            }

        return {
            "status": "Safe",
            "summary": "Traffic is normal.",
        }
