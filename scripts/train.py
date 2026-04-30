"""Training script for the cybersecurity intrusion detection model."""

from __future__ import annotations

import logging
import pickle
from pathlib import Path

import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from torch.utils.data import DataLoader, Dataset

from src.model.balancing import get_balanced_data, get_loss_weights

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CICIDSDataset(Dataset):
    """PyTorch Dataset for CIC-IDS2017 data."""

    def __init__(
        self,
        X: pd.DataFrame,
        y: pd.Series,
    ) -> None:
        """Initialize dataset.

        Args:
            X: Feature DataFrame.
            y: Target labels.
        """
        self.X = torch.tensor(X.values, dtype=torch.float32)
        self.y = torch.tensor(y.values, dtype=torch.long)

    def __len__(self) -> int:
        return len(self.X)

    def __getitem__(self, idx: int) -> tuple[torch.Tensor, torch.Tensor]:
        return self.X[idx], self.y[idx]


class NeuralNetwork(nn.Module):
    """Neural network for intrusion detection."""

    def __init__(
        self,
        input_size: int,
        num_classes: int,
        dropout: float = 0.3,
    ) -> None:
        """Initialize network.

        Args:
            input_size: Number of input features.
            num_classes: Number of output classes.
            dropout: Dropout probability.
        """
        super().__init__()
        self.layer1 = nn.Linear(input_size, 128)
        self.layer2 = nn.Linear(128, 64)
        self.layer3 = nn.Linear(64, num_classes)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.relu(self.layer1(x))
        x = self.dropout(x)
        x = self.relu(self.layer2(x))
        x = self.dropout(x)
        x = self.layer3(x)
        return x


def train_model(
    data_path: Path,
    checkpoint_dir: Path,
    num_epochs: int = 10,
    batch_size: int = 256,
    learning_rate: float = 0.001,
) -> None:
    """Train the intrusion detection model.

    Args:
        data_path: Path to processed CSV file.
        checkpoint_dir: Directory to save model checkpoints.
        num_epochs: Number of training epochs.
        batch_size: Training batch size.
        learning_rate: Optimizer learning rate.
    """
    # Load processed data
    logger.info(f"Loading data from {data_path}")
    df = pd.read_csv(data_path)

    # Balance dataset
    logger.info("Balancing dataset...")
    df_balanced = get_balanced_data(df)

    # Separate features and target (Super_Label is the target after balancing)
    X = df_balanced.drop(columns=["Super_Label"])
    y = df_balanced["Super_Label"]

    # Encode labels
    logger.info("Encoding labels...")
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    num_classes = len(label_encoder.classes_)
    logger.info(f"Classes: {label_encoder.classes_}")

    # Split data
    logger.info("Splitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded,
    )

    # Scale features
    logger.info("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    X_train_scaled = pd.DataFrame(X_train_scaled, columns=X.columns)
    X_test_scaled = pd.DataFrame(X_test_scaled, columns=X.columns)

    # Create datasets
    train_dataset = CICIDSDataset(X_train_scaled, pd.Series(y_train))
    test_dataset = CICIDSDataset(X_test_scaled, pd.Series(y_test))

    # Create dataloaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size,
        shuffle=False,
    )

    # Initialize model
    input_size = X.shape[1]
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")

    model = NeuralNetwork(input_size, num_classes).to(device)

    # Compute class weights for loss function
    logger.info("Computing class weights...")
    class_weights = get_loss_weights(pd.Series(y_train)).to(device)

    # Loss and optimizer
    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)

    # Training loop
    logger.info(f"Starting training for {num_epochs} epochs...")
    model.train()

    for epoch in range(num_epochs):
        epoch_loss = 0.0
        num_batches = 0

        for batch_X, batch_y in train_loader:
            batch_X = batch_X.to(device)
            batch_y = batch_y.to(device)

            # Forward pass
            optimizer.zero_grad()
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)

            # Backward pass
            loss.backward()
            optimizer.step()

            epoch_loss += loss.item()
            num_batches += 1

        avg_loss = epoch_loss / num_batches
        logger.info(f"Epoch {epoch + 1}/{num_epochs}, Loss: {avg_loss:.4f}")

    logger.info("Training complete!")

    # Save checkpoints
    logger.info(f"Saving checkpoints to {checkpoint_dir}")
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    # Save model
    model_path = checkpoint_dir / "model.pt"
    torch.save(model.state_dict(), model_path)

    # Save scaler
    scaler_path = checkpoint_dir / "scaler.pkl"
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)

    # Save encoder
    encoder_path = checkpoint_dir / "encoder.pkl"
    with open(encoder_path, "wb") as f:
        pickle.dump(label_encoder, f)

    logger.info("All artifacts saved successfully!")


if __name__ == "__main__":
    project_root = Path(__file__).parent.parent
    data_path = project_root / "dataset" / "processed" / "golden_ids2017.csv"
    checkpoint_dir = project_root / "checkpoints"

    train_model(data_path, checkpoint_dir)
