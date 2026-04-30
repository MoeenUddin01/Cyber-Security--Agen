"""Class balancing utilities for handling imbalanced CIC-IDS2017 dataset."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import numpy as np
import pandas as pd
import torch
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from sklearn.utils.class_weight import compute_class_weight

if TYPE_CHECKING:
    from pandas import DataFrame, Series

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BENIGN_DOWNSAMPLE_SIZE = 500_000
MIN_SAMPLES_PER_CLASS = 20_000
RANDOM_STATE = 42

# Super-Class regex patterns for matching attack types
SUPER_CLASS_PATTERNS = {
    "DOS_ATTACK": r"(DDoS|DoS)",
    "WEB_ATTACK": r"Web Attack",
    "BRUTE_FORCE": r"Patator",
    "INFILTRATION_GENERAL": r"(Infiltration|Bot|Heartbleed)",
    "SCANNING": r"PortScan",
}


def apply_super_classes(df: DataFrame) -> DataFrame:
    """Map micro-classes to Super-Classes using regex pattern matching.

    Creates a new 'Super_Label' column with 6 Super-Classes while preserving
    the original 'Label' column. Uses regex to handle weird characters.

    Mapping rules:
        - DDoS/DoS variants -> DOS_ATTACK
        - Web Attack variants -> WEB_ATTACK
        - Patator variants -> BRUTE_FORCE
        - Infiltration/Bot/Heartbleed -> INFILTRATION_GENERAL
        - PortScan -> SCANNING
        - BENIGN -> BENIGN

    Args:
        df: DataFrame with original 'Label' column.

    Returns:
        DataFrame with new 'Super_Label' column containing 6 Super-Classes.

    Raises:
        ValueError: If 'Label' column is missing.
    """
    if "Label" not in df.columns:
        raise ValueError("DataFrame must contain a 'Label' column")

    df = df.copy()

    # Step 1: Strip whitespace from labels
    df["Label"] = df["Label"].str.strip()
    labels = df["Label"]

    # Step 2: Initialize Super_Label with original values
    df["Super_Label"] = labels.copy()

    # Step 3: Apply regex-based mapping
    for super_class, pattern in SUPER_CLASS_PATTERNS.items():
        mask = labels.str.contains(pattern, case=False, na=False, regex=True)
        df.loc[mask, "Super_Label"] = super_class

    # Step 4: Flag unmapped labels (not BENIGN and not matched)
    unmapped_mask = ~df["Super_Label"].isin(
        list(SUPER_CLASS_PATTERNS.keys()) + ["BENIGN"]
    )
    unmapped_labels = df.loc[unmapped_mask, "Label"].unique()

    if len(unmapped_labels) > 0:
        logger.warning(f"Unmapped labels detected: {list(unmapped_labels)}")
        logger.warning(f"  Count: {unmapped_mask.sum()} rows")
    else:
        logger.info("All labels successfully mapped to Super-Classes")

    # Step 5: Verification - Print final value counts
    value_counts = df["Super_Label"].value_counts()
    logger.info("Final Super-Class distribution:")
    for label, count in value_counts.items():
        logger.info(f"  {label}: {count}")

    logger.info(f"Total Super-Classes: {len(value_counts)}")

    return df


def get_balanced_data(df: DataFrame) -> DataFrame:
    """Balance dataset using Group-then-SMOTE strategy.

    Implements 3-Step Super-Class Pipeline:
    1. Map micro-classes to Super-Classes (creates Super_Label column)
    2. Apply RandomUnderSampler to reduce BENIGN to 500,000
    3. Apply SMOTE to boost small Super-Classes to 5,000 samples minimum

    Args:
        df: Raw DataFrame containing all classes with a 'Label' column.
            Will use apply_super_classes() to create 'Super_Label'.

    Returns:
        Balanced DataFrame with Super_Label as the target column.

    Raises:
        ValueError: If 'Label' column is missing or insufficient data.
    """
    if "Label" not in df.columns:
        raise ValueError("DataFrame must contain a 'Label' column")

    # Step 1: Map to Super-Classes (creates Super_Label column)
    logger.info("Step 1: Mapping micro-classes to Super-Classes...")
    df = apply_super_classes(df)

    # Use Super_Label for balancing
    if "Super_Label" not in df.columns:
        raise ValueError("apply_super_classes() failed to create 'Super_Label' column")

    logger.info("Class distribution for balancing (Super_Label):")
    super_counts = df["Super_Label"].value_counts()
    for label, count in super_counts.items():
        logger.info(f"  {label}: {count}")

    # Step 2 & 3: Resample using imbalanced-learn
    logger.info("Step 2-3: Applying RandomUnderSampler and SMOTE...")

    # Features are all columns except Label and Super_Label
    feature_cols = [col for col in df.columns if col not in ["Label", "Super_Label"]]
    X = df[feature_cols]
    y = df["Super_Label"]

    # First, downsample BENIGN to 500k
    logger.info(f"  Downsampling BENIGN to {BENIGN_DOWNSAMPLE_SIZE}...")
    rus = RandomUnderSampler(
        sampling_strategy={"BENIGN": BENIGN_DOWNSAMPLE_SIZE},
        random_state=RANDOM_STATE,
    )
    X_resampled, y_resampled = rus.fit_resample(X, y)

    # Then, apply SMOTE to boost minority classes to 5k
    current_counts = pd.Series(y_resampled).value_counts()
    smote_strategy = {}

    for cls, count in current_counts.items():
        if cls != "BENIGN" and count < MIN_SAMPLES_PER_CLASS:
            smote_strategy[cls] = MIN_SAMPLES_PER_CLASS

    if smote_strategy:
        logger.info(f"  Applying SMOTE to boost classes: {smote_strategy}")
        smote = SMOTE(
            sampling_strategy=smote_strategy,
            random_state=RANDOM_STATE,
            k_neighbors=min(5, min(current_counts[current_counts > 1]) - 1),
        )
        X_resampled, y_resampled = smote.fit_resample(X_resampled, y_resampled)

    # Create balanced DataFrame with Super_Label as target
    balanced_df = pd.DataFrame(X_resampled, columns=feature_cols)
    balanced_df["Super_Label"] = y_resampled

    # Shuffle
    balanced_df = balanced_df.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)

    # Verification
    final_counts = balanced_df["Super_Label"].value_counts()
    logger.info("Final class distribution after balancing:")
    for label, count in final_counts.items():
        logger.info(f"  {label}: {count}")

    logger.info(f"Total samples: {len(balanced_df)}")
    logger.info(f"Number of Super-Classes: {len(final_counts)}")

    return balanced_df


def get_loss_weights(y: Series | np.ndarray) -> torch.Tensor:
    """Compute balanced class weights for PyTorch CrossEntropyLoss.

    Uses sklearn's compute_class_weight with 'balanced' strategy to account
    for class imbalance in the loss function.

    Args:
        y: Target labels as pandas Series or numpy array.

    Returns:
        PyTorch tensor of weights aligned with class indices.

    Raises:
        ValueError: If y is empty or contains only one class.
    """
    if len(y) == 0:
        raise ValueError("Target array cannot be empty")

    # Convert to numpy if pandas Series
    if isinstance(y, pd.Series):
        y = y.values

    classes = np.unique(y)

    if len(classes) < 2:
        raise ValueError(f"Need at least 2 classes, found {len(classes)}")

    # Compute balanced weights
    weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=y,
    )

    # Convert to PyTorch tensor
    weight_tensor = torch.tensor(weights, dtype=torch.float32)

    logger.info("Computed loss weights:")
    for cls, weight in zip(classes, weights):
        logger.info(f"  {cls}: {weight:.4f}")

    return weight_tensor
