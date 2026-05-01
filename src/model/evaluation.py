"""Model evaluation utilities for generating classification reports and confusion matrices."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import torch
from sklearn.metrics import classification_report, confusion_matrix

if TYPE_CHECKING:
    from sklearn.preprocessing import LabelEncoder
    from torch.utils.data import DataLoader


def evaluate_model(
    model: torch.nn.Module,
    test_loader: DataLoader,
    device: torch.device,
    label_encoder: LabelEncoder,
) -> dict:
    """Evaluate model and generate classification report with confusion matrix.

    Args:
        model: Trained PyTorch model.
        test_loader: Test data loader.
        device: Device to run evaluation on.
        label_encoder: Fitted LabelEncoder for converting indices to class names.

    Returns:
        Classification report as a dictionary.
    """
    model.eval()
    y_true = []
    y_pred = []

    with torch.no_grad():
        for inputs, labels in test_loader:
            inputs, labels = inputs.to(device), labels.to(device)
            outputs = model(inputs)
            _, predicted = torch.max(outputs, 1)

            y_true.extend(labels.cpu().numpy())
            y_pred.extend(predicted.cpu().numpy())

    # Get class names from encoder
    class_names = label_encoder.classes_

    # 1. Print Text Report
    print("\n" + "=" * 30)
    print("FINAL CLASSIFICATION REPORT")
    print("=" * 30)
    print(classification_report(y_true, y_pred, target_names=class_names))

    # 2. Generate Confusion Matrix Plot
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_names, yticklabels=class_names)
    plt.xlabel('Predicted Labels')
    plt.ylabel('True Labels')
    plt.title('Security Threat Detection - Confusion Matrix')
    plt.tight_layout()

    # Save the visual
    artifacts_dir = Path(__file__).parent.parent.parent / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    cm_path = artifacts_dir / "confusion_matrix.png"
    plt.savefig(cm_path)
    print(f"Confusion Matrix saved to '{cm_path}'")
    plt.close()

    return classification_report(y_true, y_pred, output_dict=True)


if __name__ == "__main__":
    # Quick test with dummy data
    from sklearn.preprocessing import LabelEncoder
    import torch.nn as nn

    # Create dummy label encoder
    le = LabelEncoder()
    le.fit(["BENIGN", "DOS_ATTACK", "WEB_ATTACK", "BRUTE_FORCE", "INFILTRATION_GENERAL", "PortScan"])

    # Create dummy model and data
    class DummyModel(nn.Module):
        def forward(self, x):
            return torch.randn(x.shape[0], 6)

    model = DummyModel()
    device = torch.device("cpu")

    # Create dummy loader
    dummy_data = [(torch.randn(4, 17), torch.randint(0, 6, (4,))) for _ in range(3)]

    print("Testing evaluate_model function...")
    report = evaluate_model(model, dummy_data, device, le)
    print(f"Report generated with keys: {list(report.keys())}")
