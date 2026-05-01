"""Training script for the cybersecurity classification model."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def train_epoch(
    model: nn.Module,
    train_loader: DataLoader,
    criterion: nn.Module,
    optimizer: optim.Optimizer,
    device: torch.device,
) -> float:
    """Train for one epoch.

    Args:
        model: The neural network model.
        train_loader: Training data loader.
        criterion: Loss function.
        optimizer: Optimizer.
        device: Device to train on.

    Returns:
        Average loss for the epoch.
    """
    model.train()
    total_loss = 0.0
    num_batches = 0

    for X_batch, y_batch in train_loader:
        X_batch, y_batch = X_batch.to(device), y_batch.to(device)

        optimizer.zero_grad()
        outputs = model(X_batch)
        loss = criterion(outputs, y_batch)
        loss.backward()
        optimizer.step()

        total_loss += loss.item()
        num_batches += 1

    return total_loss / num_batches if num_batches > 0 else 0.0


def evaluate(
    model: nn.Module,
    test_loader: DataLoader,
    criterion: nn.Module,
    device: torch.device,
) -> tuple[float, float]:
    """Evaluate the model on test data.

    Args:
        model: The neural network model.
        test_loader: Test data loader.
        criterion: Loss function.
        device: Device to evaluate on.

    Returns:
        Tuple of (average loss, accuracy).
    """
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0

    with torch.no_grad():
        for X_batch, y_batch in test_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)

            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            total_loss += loss.item()

            _, predicted = torch.max(outputs, 1)
            total += y_batch.size(0)
            correct += (predicted == y_batch).sum().item()

    avg_loss = total_loss / len(test_loader) if len(test_loader) > 0 else 0.0
    accuracy = 100.0 * correct / total if total > 0 else 0.0

    return avg_loss, accuracy


def run_training_loop(
    model: nn.Module,
    train_loader: DataLoader,
    test_loader: DataLoader,
    device: torch.device,
    epochs: int = 50,
    lr: float = 0.001,
) -> dict[str, Any]:
    """Run the training loop for the model.

    Args:
        model: The neural network model to train.
        train_loader: Training data loader.
        test_loader: Test data loader.
        device: Device to train on.
        epochs: Number of training epochs.
        lr: Learning rate.

    Returns:
        Dictionary containing training metrics and the trained model.
    """
    # Loss and optimizer (NLLLoss for log_softmax output)
    criterion = nn.NLLLoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)

    # Track Metrics: Store loss and accuracy for every epoch
    training_metrics: dict[str, Any] = {
        "epochs": [],
        "train_loss": [],
        "test_loss": [],
        "accuracy": [],
    }

    # Training loop
    best_accuracy = 0.0
    logger.info(f"Starting training for {epochs} epochs...")

    for epoch in range(epochs):
        train_loss = train_epoch(model, train_loader, criterion, optimizer, device)
        test_loss, accuracy = evaluate(model, test_loader, criterion, device)

        # Track metrics
        training_metrics["epochs"].append(epoch + 1)
        training_metrics["train_loss"].append(round(train_loss, 4))
        training_metrics["test_loss"].append(round(test_loss, 4))
        training_metrics["accuracy"].append(round(accuracy, 2))

        logger.info(
            f"Epoch [{epoch+1}/{epochs}] "
            f"Train Loss: {train_loss:.4f}, "
            f"Test Loss: {test_loss:.4f}, "
            f"Accuracy: {accuracy:.2f}%"
        )

        # Track best accuracy
        if accuracy > best_accuracy:
            best_accuracy = accuracy

    logger.info(f"Training complete. Best accuracy: {best_accuracy:.2f}%")

    return {
        "training_metrics": training_metrics,
        "best_accuracy": best_accuracy,
        "model": model,
    }
