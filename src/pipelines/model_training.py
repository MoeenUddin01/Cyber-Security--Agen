"""Model training pipeline for the cybersecurity classification system."""

from __future__ import annotations

from pathlib import Path

import torch
import yaml

from src.data.loader import prepare_loaders
from src.model.evaluation import evaluate_model
from src.model.model import IDS_Model
from src.model.train import run_training_loop


def load_config(config_path: str | Path = "config.yaml") -> dict:
    """Load configuration from YAML file.
    
    Args:
        config_path: Path to config.yaml file.
        
    Returns:
        Configuration dictionary.
    """
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def train_model_pipeline(
    config_path: str | Path = "config.yaml",
) -> dict:
    """Execute the full model training pipeline.

    Args:
        config_path: Path to config.yaml file.

    Returns:
        Dictionary containing training results and metrics.
    """
    # Load configuration
    config = load_config(config_path)
    
    # Setup: Create the artifacts/ directory
    project_root = Path(config["paths"]["project_root"])
    artifacts_dir = project_root / config["paths"]["artifacts_dir"]
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Determine device - Force CPU due to GPU compatibility issues
    print('!!! Incompatible GPU detected. Switching to CPU for stability !!!')
    device = torch.device('cpu')

    # Data: Call prepare_loaders() to get the training and testing data
    csv_path = project_root / config["paths"]["balanced_dataset"]
    batch_size = config["data"]["batch_size"]

    train_loader, test_loader, num_classes, label_encoder = prepare_loaders(
        csv_path, batch_size=batch_size
    )

    # Get input dimension from first batch
    sample_batch = next(iter(train_loader))
    input_dim = sample_batch[0].shape[1]

    # Model: Initialize IDS_Model
    model_config = config["model"]
    model = IDS_Model(
        input_size=input_dim,
        num_classes=model_config["num_classes"],
    ).to(device)

    # Execution: Call run_training_loop()
    training_config = config["training"]
    training_result = run_training_loop(
        model=model,
        train_loader=train_loader,
        test_loader=test_loader,
        device=device,
        epochs=training_config["epochs"],
        lr=training_config["learning_rate"],
    )

    trained_model = training_result["model"]
    best_accuracy = training_result["best_accuracy"]

    # Save trained model weights
    model_path = artifacts_dir / config["artifacts"]["model_file"]
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
