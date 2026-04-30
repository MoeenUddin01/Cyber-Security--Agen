"""Data preprocessing pipeline for merging and cleaning CSV files."""

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


def preprocess_data(
    raw_dir: Path,
    output_path: Path,
) -> None:
    """Merge all CSV files and clean data according to specifications.

    Args:
        raw_dir: Directory containing raw CSV files.
        output_path: Path where the processed CSV will be saved.

    Raises:
        FileNotFoundError: If no CSV files are found in raw_dir.
    """
    csv_files = list(raw_dir.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {raw_dir}")

    logger.info(f"Found {len(csv_files)} CSV files to process")

    cleaned_dfs = []

    for csv_file in csv_files:
        logger.info(f"Processing {csv_file.name}")

        df = pd.read_csv(csv_file)

        # Strip whitespace from headers
        df.columns = df.columns.str.strip()

        # Select golden features
        df = df[GOLDEN_FEATURES].copy()

        # Replace inf with column maximums
        for col in df.columns:
            if col != "Label":
                col_max = df[col].replace([float("inf"), -float("inf")], pd.NA).max()
                df[col] = df[col].replace([float("inf"), -float("inf")], col_max)

        # Drop NaN rows
        initial_rows = len(df)
        df = df.dropna()
        dropped_rows = initial_rows - len(df)

        cleaned_dfs.append(df)
        logger.info(f"  Kept {len(df)} rows (dropped {dropped_rows} NaN rows)")

    # Merge all dataframes
    master_df = pd.concat(cleaned_dfs, ignore_index=True)

    # Create output directory if needed
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save final dataframe
    master_df.to_csv(output_path, index=False)

    logger.info(f"Saved {len(master_df)} rows with {len(master_df.columns)} columns to {output_path}")


if __name__ == "__main__":
    project_root = Path(__file__).parent.parent.parent
    raw_dir = project_root / "dataset" / "raw"
    output_path = project_root / "dataset" / "processed" / "golden_ids2017.csv"

    preprocess_data(raw_dir, output_path)
