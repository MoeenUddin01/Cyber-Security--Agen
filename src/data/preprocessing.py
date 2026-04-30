"""Data preprocessing utilities for the cybersecurity dataset."""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GOLDEN_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
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
    "Label",
]


def process_and_merge_data(
    raw_dir: Path,
    output_dir: Path,
    output_filename: str = "cicids2017_golden_features.csv",
) -> None:
    """Process and merge CSV files with feature pruning and cleaning.

    Args:
        raw_dir: Path to directory containing raw CSV files.
        output_dir: Path to directory where processed data will be saved.
        output_filename: Name of the output CSV file.

    Raises:
        FileNotFoundError: If no CSV files are found in raw_dir.
    """
    csv_files = list(raw_dir.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {raw_dir}")

    logger.info(f"Found {len(csv_files)} CSV files in {raw_dir}")

    cleaned_dfs = []

    for csv_file in csv_files:
        logger.info(f"Processing {csv_file.name}")

        df = pd.read_csv(csv_file)

        # Strip headers to fix hidden spaces
        df.columns = df.columns.str.strip()

        # Select only golden features
        df = df[GOLDEN_FEATURES].copy()

        # Replace inf values with column maximum
        for col in df.columns:
            if col != "Label":
                col_max = df[col].replace([float("inf"), -float("inf")], pd.NA).max()
                df[col] = df[col].replace([float("inf"), -float("inf")], col_max)

        # Drop rows with NaN
        df = df.dropna()

        cleaned_dfs.append(df)
        logger.info(f"  Cleaned shape: {df.shape}")

    # Concatenate all cleaned dataframes
    master_df = pd.concat(cleaned_dfs, ignore_index=True)

    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save the final result
    output_path = output_dir / output_filename
    master_df.to_csv(output_path, index=False)

    # Print final summary
    unique_labels = master_df["Label"].unique().tolist()
    print(
        f"Master file created with {len(master_df)} rows and "
        f"{len(master_df.columns) - 1} features. "
        f"Target classes preserved: {unique_labels}"
    )

    logger.info(f"Saved processed data to {output_path}")


if __name__ == "__main__":
    project_root = Path(__file__).parent.parent.parent
    raw_dir = project_root / "dataset" / "raw"
    output_dir = project_root / "dataset" / "processed"

    process_and_merge_data(raw_dir, output_dir)