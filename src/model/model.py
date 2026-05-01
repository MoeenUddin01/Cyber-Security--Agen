"""Neural network model definition for cybersecurity classification."""

import torch
import torch.nn as nn
import torch.nn.functional as F


class IDS_Model(nn.Module):
    """Intrusion Detection System Model for network traffic classification.

    A 4-layer MLP with batch normalization and dropout for classification
    of Super-Classes (BENIGN, DOS_ATTACK, WEB_ATTACK, BRUTE_FORCE,
    INFILTRATION_GENERAL, PortScan).

    Args:
        input_size: Number of input features (17 for golden features).
        num_classes: Number of output classes (6 Super-Classes).
    """

    def __init__(self, input_size=17, num_classes=6):
        super(IDS_Model, self).__init__()

        # Layer 1: Input -> 256
        self.fc1 = nn.Linear(input_size, 256)
        self.bn1 = nn.BatchNorm1d(256)
        self.dropout1 = nn.Dropout(0.3)

        # Layer 2: 256 -> 256
        self.fc2 = nn.Linear(256, 256)
        self.bn2 = nn.BatchNorm1d(256)
        self.dropout2 = nn.Dropout(0.3)

        # Layer 3: 256 -> 64
        self.fc3 = nn.Linear(256, 64)

        # Output Layer: 64 -> num_classes
        self.fc4 = nn.Linear(64, num_classes)

    def forward(self, x):
        """Forward pass through the network.

        Args:
            x: Input tensor of shape (batch_size, input_size).

        Returns:
            Output log probabilities of shape (batch_size, num_classes).
        """
        # Pass through Layer 1
        x = F.relu(self.bn1(self.fc1(x)))
        x = self.dropout1(x)

        # Pass through Layer 2
        x = F.relu(self.bn2(self.fc2(x)))
        x = self.dropout2(x)

        # Pass through Layer 3
        x = F.relu(self.fc3(x))

        # Output (LogSoftmax for NLLLoss)
        return F.log_softmax(self.fc4(x), dim=1)


if __name__ == "__main__":
    # Quick test
    model = IDS_Model(input_size=17, num_classes=6)
    sample_input = torch.randn(32, 17)
    output = model(sample_input)
    print(f"Input shape: {sample_input.shape}")
    print(f"Output shape: {output.shape}")
    print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")
