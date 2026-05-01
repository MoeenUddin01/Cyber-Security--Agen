"""Data loading utilities with preprocessing and DataLoader creation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import joblib
import pandas as pd
import torch
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from torch.utils.data import DataLoader, TensorDataset

if TYPE_CHECKING:
    from torch.utils.data import DataLoader as TorchDataLoader

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 17 Golden Features (excluding Label)
FEATURE_COLS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Bwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Max",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
]

TARGET_COL = "Super_Label"


def prepare_loaders(
    csv_path: str | Path,
    batch_size: int = 1024,
    random_state: int = 42,
) -> tuple[TorchDataLoader, TorchDataLoader, int, LabelEncoder]:
    """Load data, preprocess, and create PyTorch DataLoaders.

    Args:
        csv_path: Path to the balanced_dataset.csv file.
        batch_size: Batch size for DataLoaders.
        random_state: Random seed for reproducibility.

    Returns:
        Tuple of (train_loader, test_loader, num_classes, label_encoder).

    Raises:
        FileNotFoundError: If csv_path does not exist.
        ValueError: If required columns are missing.
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    # Load data
    logger.info(f"Loading data from {csv_path}")
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()  # Remove any hidden spaces
    logger.info(f"Loaded {len(df)} rows")

    # Verify columns exist
    missing_features = [col for col in FEATURE_COLS if col not in df.columns]
    if missing_features:
        raise ValueError(f"Missing feature columns: {missing_features}")
    if TARGET_COL not in df.columns:
        raise ValueError(f"Missing target column: {TARGET_COL}")

    # Separate X (17 features) and y (Super_Label)
    X = df[FEATURE_COLS]
    y = df[TARGET_COL]

    logger.info(f"Features shape: {X.shape}, Target distribution:\n{y.value_counts()}")

    # Split: 80/20 with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=random_state
    )
    logger.info(
        f"Split complete - Train: {len(X_train)}, Test: {len(X_test)}"
    )

    # Scale: Fit on X_train only, transform both
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    logger.info("StandardScaler fitted on training data and applied to both sets")

    # Encode: Fit on y_train, transform both
    label_encoder = LabelEncoder()
    y_train_encoded = label_encoder.fit_transform(y_train)
    y_test_encoded = label_encoder.transform(y_test)
    num_classes = len(label_encoder.classes_)
    logger.info(
        f"LabelEncoder fitted - Classes: {label_encoder.classes_}, "
        f"Number of classes: {num_classes}"
    )

    # Save artifacts to artifacts/ folder
    artifacts_dir = Path(__file__).parent.parent.parent / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    scaler_path = artifacts_dir / "scaler.joblib"
    encoder_path = artifacts_dir / "label_encoder.joblib"

    joblib.dump(scaler, scaler_path)
    joblib.dump(label_encoder, encoder_path)
    logger.info(f"Saved artifacts to {artifacts_dir}")

    # Convert to PyTorch tensors
    X_train_tensor = torch.FloatTensor(X_train_scaled)
    X_test_tensor = torch.FloatTensor(X_test_scaled)
    y_train_tensor = torch.LongTensor(y_train_encoded)
    y_test_tensor = torch.LongTensor(y_test_encoded)

    # Create TensorDatasets
    train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
    test_dataset = TensorDataset(X_test_tensor, y_test_tensor)

    # Create DataLoaders
    train_loader = DataLoader(
        train_dataset, batch_size=batch_size, shuffle=True, drop_last=False
    )
    test_loader = DataLoader(
        test_dataset, batch_size=batch_size, shuffle=False, drop_last=False
    )

    logger.info(
        f"DataLoaders created - Train batches: {len(train_loader)}, "
        f"Test batches: {len(test_loader)}"
    )

    return train_loader, test_loader, num_classes, label_encoder


if __name__ == "__main__":
    # Test the loader
    project_root = Path(__file__).parent.parent.parent
    csv_path = project_root / "dataset" / "processed" / "balanced_dataset.csv"

    train_loader, test_loader, num_classes, label_encoder = prepare_loaders(csv_path)
    print(f"\nNumber of classes: {num_classes}")
    print(f"Feature count: {17}")
    print(f"Train batches: {len(train_loader)}")
    print(f"Test batches: {len(test_loader)}")
    print(f"Classes: {label_encoder.classes_}")

    # Inspect a batch
    for X_batch, y_batch in train_loader:
        print(f"\nSample batch - X shape: {X_batch.shape}, y shape: {y_batch.shape}")
        print(f"X dtype: {X_batch.dtype}, y dtype: {y_batch.dtype}")
        break
