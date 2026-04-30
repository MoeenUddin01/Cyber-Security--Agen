"""Consolidated data preprocessing and balancing pipeline."""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from src.model.balancing import apply_super_classes, get_balanced_data

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Golden Features from the original specification
GOLDEN_FEATURES = [
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


def consolidate_csvs(raw_dir: Path) -> pd.DataFrame:
    """Load and consolidate all CSV files from raw directory.

    Args:
        raw_dir: Directory containing raw CSV files.

    Returns:
        Consolidated DataFrame with all data.

    Raises:
        FileNotFoundError: If no CSV files are found.
    """
    csv_files = list(raw_dir.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {raw_dir}")

    logger.info(f"Found {len(csv_files)} CSV files to consolidate")

    dataframes = []
    for csv_file in csv_files:
        logger.info(f"  Loading {csv_file.name}")
        df = pd.read_csv(csv_file)
        dataframes.append(df)

    consolidated_df = pd.concat(dataframes, ignore_index=True)
    logger.info(f"Consolidated {len(consolidated_df)} rows from {len(csv_files)} files")

    return consolidated_df


def clean_features(df: pd.DataFrame) -> pd.DataFrame:
    """Clean features: strip whitespace, filter golden features, handle inf/NaN.

    Args:
        df: Raw consolidated DataFrame.

    Returns:
        Cleaned DataFrame with only Golden Features + Label.
    """
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Check if 'Label' column exists (might be named differently)
    label_col = None
    for col in df.columns:
        if col.lower() == "label":
            label_col = col
            break

    if label_col is None:
        raise ValueError("No 'Label' column found in dataset")

    # Rename to standard 'Label' if needed
    if label_col != "Label":
        df = df.rename(columns={label_col: "Label"})

    # Filter for Golden Features + Label
    # Note: Dataset uses "Total Backward Packets" not "Total Bwd Packets"
    feature_cols = []
    for feature in GOLDEN_FEATURES:
        # Try to find the column (handles variations like Bwd vs Backward)
        if feature in df.columns:
            feature_cols.append(feature)
        elif feature == "Total Bwd Packets" and "Total Backward Packets" in df.columns:
            feature_cols.append("Total Backward Packets")

    if len(feature_cols) != len(GOLDEN_FEATURES):
        missing = set(GOLDEN_FEATURES) - set(df.columns)
        # Check if it's just the Bwd/Backward naming
        if "Total Bwd Packets" in missing and "Total Backward Packets" in df.columns:
            missing.remove("Total Bwd Packets")
        if missing:
            logger.warning(f"Missing features: {missing}")

    # Select only Golden Features + Label
    selected_cols = feature_cols + ["Label"]
    df = df[selected_cols].copy()

    # Rename Total Backward Packets to Total Bwd Packets for consistency
    if "Total Backward Packets" in df.columns:
        df = df.rename(columns={"Total Backward Packets": "Total Bwd Packets"})

    logger.info(f"Selected {len(feature_cols)} features + Label")

    # Handle inf values: replace with column maximum
    for col in df.columns:
        if col != "Label":
            # Replace inf with NaN temporarily, then fill with max
            col_max = df[col].replace([float("inf"), -float("inf")], pd.NA).max()
            df[col] = df[col].replace([float("inf"), -float("inf")], col_max)

    # Drop rows with NaN values
    initial_rows = len(df)
    df = df.dropna()
    dropped_rows = initial_rows - len(df)
    logger.info(f"Dropped {dropped_rows} rows with NaN/inf values")
    logger.info(f"Cleaned dataset: {len(df)} rows, {len(df.columns)} columns")

    return df


def run_preprocessing_pipeline(
    raw_dir: Path,
    output_path: Path,
) -> None:
    """Execute the full preprocessing and balancing pipeline.

    Pipeline steps:
    1. Consolidate: Load all CSVs from raw_dir
    2. Clean: Strip whitespace, filter Golden Features, handle inf/NaN
    3. Map Super-Classes: Apply apply_super_classes to create Super_Label
    4. Balance: Apply get_balanced_data (downsample BENIGN, SMOTE minority classes)
    5. Save: Export to output_path
    6. Report: Print final statistics

    Args:
        raw_dir: Directory containing raw CSV files.
        output_path: Path for the final balanced dataset.
    """
    logger.info("=" * 60)
    logger.info("STARTING PREPROCESSING AND BALANCING PIPELINE")
    logger.info("=" * 60)

    # Step 1: Consolidate
    logger.info("\n[STEP 1] Consolidating CSV files...")
    df = consolidate_csvs(raw_dir)

    # Step 2: Clean
    logger.info("\n[STEP 2] Cleaning features (strip whitespace, filter, inf/NaN)...")
    df = clean_features(df)

    # Step 3: Map Super-Classes
    logger.info("\n[STEP 3] Mapping to Super-Classes...")
    df = apply_super_classes(df)

    # Step 4: Balance
    logger.info("\n[STEP 4] Balancing dataset (RandomUnderSampler + SMOTE)...")
    logger.info(f"  - BENIGN will be downsampled to 500,000")
    logger.info(f"  - Super-Classes with < 20,000 samples will be boosted via SMOTE")
    df_balanced = get_balanced_data(df)

    # Step 5: Save
    logger.info("\n[STEP 5] Saving balanced dataset...")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df_balanced.to_csv(output_path, index=False)
    logger.info(f"Saved to: {output_path}")

    # Step 6: Report
    logger.info("\n" + "=" * 60)
    logger.info("FINAL REPORT")
    logger.info("=" * 60)
    logger.info(f"Total rows in final dataset: {len(df_balanced)}")
    logger.info(f"Total columns: {len(df_balanced.columns)}")
    logger.info("")
    logger.info("Super_Label distribution:")
    value_counts = df_balanced["Super_Label"].value_counts().sort_index()
    for label, count in value_counts.items():
        percentage = (count / len(df_balanced)) * 100
        logger.info(f"  {label:25s}: {count:8,} ({percentage:5.1f}%)")
    logger.info("-" * 40)
    logger.info(f"  {'TOTAL':25s}: {len(df_balanced):8,} (100.0%)")
    logger.info("=" * 60)


if __name__ == "__main__":
    project_root = Path(__file__).parent.parent
    raw_dir = project_root / "dataset" / "raw"
    output_path = project_root / "dataset" / "processed" / "balanced_dataset.csv"

    run_preprocessing_pipeline(raw_dir, output_path)
