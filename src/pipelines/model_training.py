"""Model training pipeline for the cybersecurity classification system."""

from __future__ import annotations

from pathlib import Path

import torch

from src.data.loader import prepare_loaders
from src.model.evaluation import evaluate_model
from src.model.model import IDS_Model
from src.model.train import run_training_loop


def train_model_pipeline(
    csv_path: str | Path | None = None,
    epochs: int = 50,
    batch_size: int = 1024,
    lr: float = 0.001,
    device: str | torch.device = "auto",
) -> dict:
    """Execute the full model training pipeline.

    Args:
        csv_path: Path to the balanced_dataset.csv file.
                   Defaults to dataset/processed/balanced_dataset.csv.
        epochs: Number of training epochs.
        batch_size: Batch size for training.
        lr: Learning rate.
        device: Device to train on ('auto', 'cuda', 'cpu', or torch.device).

    Returns:
        Dictionary containing training results and metrics.
    """
    # Setup: Create the artifacts/ directory
    project_root = Path(__file__).parent.parent.parent
    artifacts_dir = project_root / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Determine device
    if device == "auto":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    elif isinstance(device, str):
        device = torch.device(device)

    # Data: Call prepare_loaders() to get the training and testing data
    if csv_path is None:
        csv_path = project_root / "dataset" / "processed" / "balanced_dataset.csv"

    train_loader, test_loader, num_classes, label_encoder = prepare_loaders(
        csv_path, batch_size=batch_size
    )

    # Get input dimension from first batch
    sample_batch = next(iter(train_loader))
    input_dim = sample_batch[0].shape[1]

    # Model: Initialize IDS_Model
    model = IDS_Model(
        input_size=input_dim,
        num_classes=num_classes,
    ).to(device)

    # Execution: Call run_training_loop()
    training_result = run_training_loop(
        model=model,
        train_loader=train_loader,
        test_loader=test_loader,
        device=device,
        epochs=epochs,
        lr=lr,
    )

    trained_model = training_result["model"]
    best_accuracy = training_result["best_accuracy"]

    # Save trained model weights
    model_path = artifacts_dir / "ids_agent_model.pth"
    torch.save(trained_model.state_dict(), model_path)

    # Evaluation: Call evaluate_model() using the trained weights
    evaluate_model(trained_model, test_loader, device, label_encoder)

    # Logging: Print a clean summary
    print(f"\nModel trained and artifacts saved to {artifacts_dir}/")

    return {
        "model_path": model_path,
        "best_accuracy": best_accuracy,
        "artifacts_dir": artifacts_dir,
    }


if __name__ == "__main__":
    train_model_pipeline()
