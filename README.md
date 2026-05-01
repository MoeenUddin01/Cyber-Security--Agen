# Cybersecurity Intrusion Detection System

A deep learning-based network intrusion detection system using the CIC-IDS2017 dataset. This project implements feature pruning, Super-Class grouping, SMOTE balancing, and automated security response capabilities.

## Overview

This system detects network attacks using a neural network trained on network flow features. It includes:

- **Data Preprocessing**: Feature pruning from 78 to 17 golden features
- **Super-Class Grouping**: Maps 15 micro-classes to 6 attack categories
- **Class Balancing**: SMOTE + RandomUnderSampler for handling imbalance
- **Model Training**: Deep learning classifier with weighted loss
- **Security Response**: Automated IP blocking via ResponseAgent

## Dataset

**CIC-IDS2017** - Network intrusion detection dataset containing:
- 2.8M+ network flow records
- 15 attack types including DDoS, PortScan, Web Attacks, Botnet, etc.
- 78 original features pruned to 17 golden features

Raw data location: `dataset/raw/`
Processed data: `dataset/processed/golden_ids2017.csv`

## Super-Class Grouping

To improve model performance on rare attack types, micro-classes are grouped into 6 Super-Classes:

| Super-Class | Micro-Classes Included |
|-------------|----------------------|
| **BENIGN** | Normal traffic (downsampled to 500k) |
| **DOS_ATTACK** | DDoS, DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest |
| **WEB_ATTACK** | Web Attack - Brute Force, XSS, Sql Injection |
| **BRUTE_FORCE** | FTP-Patator, SSH-Patator |
| **INFILTRATION_GENERAL** | Bot, Infiltration, Heartbleed |
| **PortScan** | Port scanning attacks |

**Balancing Strategy:**
- SMOTE: Boost minority Super-Classes to 5,000 samples minimum
- RandomUnderSampler: Reduce BENIGN to 500,000 samples
- Result: ~550k balanced samples across 6 meaningful categories

## Golden Features

The 17 selected features for model training:

1. Destination Port
2. Flow Duration
3. Total Fwd Packets
4. Total Backward Packets
5. Total Length of Fwd Packets
6. Fwd Packet Length Max/Mean/Std
7. Bwd Packet Length Max/Mean/Std
8. Flow Bytes/s
9. Flow Packets/s
10. Flow IAT Mean/Max
11. Init_Win_bytes_forward/backward
12. Label (target)

## Setup

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or: .venv\Scripts\activate  # Windows

# Install dependencies
uv sync
```

## Usage

### Data Preprocessing

Process and merge raw CSV files with feature pruning and balancing:

```bash
python scripts/run_preprocessing_pipeline.py
```

This creates `dataset/processed/golden_ids2017.csv` with 18 columns (17 features + Label).

**Note:** Requires raw CIC-IDS2017 CSV files in `dataset/raw/` directory.

### Model Training

Train the classifier with Super-Class grouping and SMOTE balancing:

```bash
python scripts/train.py
```

**Note:** The training script expects preprocessed data in `dataset/processed/golden_ids2017.csv`.

Features:
- Automatic Super-Class grouping via `apply_super_classes()`
- SMOTE oversampling for minority classes
- Class weights in CrossEntropyLoss for imbalance handling
- Saves model, scaler, and encoder to `checkpoints/` (when fully implemented)

### Model Evaluation

**Status:** Not yet implemented.

Planned evaluation features:
- Confusion matrix visualization
- Per-class precision/recall/F1
- ROC curves and AUC scores

## Project Structure

```
cyber_security/
├── src/                          # Core library
│   ├── data/
│   │   ├── preprocessing.py      # Feature pruning and data cleaning
│   │   ├── loader.py             # Dataset loading utilities (placeholder)
│   │   └── dataset.py            # PyTorch dataset classes (placeholder)
│   ├── model/
│   │   ├── model.py              # Neural network architecture (placeholder)
│   │   ├── train.py              # Training loop (placeholder)
│   │   ├── evaluation.py         # Metrics computation (placeholder)
│   │   ├── prediction.py         # Inference utilities (placeholder)
│   │   └── balancing.py          # Super-Class grouping & SMOTE (implemented)
│   ├── agents/
│   │   └── response_agent.py     # Automated response agent
│   ├── engine/
│   │   └── tools.py              # Security response tools (IP blocking)
│   ├── pipelines/
│   │   ├── data_preprocessing.py # Pipeline orchestration (placeholder)
│   │   ├── model_training_pipeline.py  # (placeholder)
│   │   └── model_evaluation.py   # (placeholder)
│   └── utils.py                  # Shared utilities
├── scripts/
│   ├── run_preprocessing_pipeline.py  # Full preprocessing pipeline
│   └── train.py                  # Model training script
├── dataset/
│   ├── raw/                      # Original CIC-IDS2017 CSV files
│   └── processed/                # Cleaned and merged data
├── notebook/                     # Jupyter notebooks for experiments
├── main.py                       # Placeholder entry point
├── pyproject.toml                # Project dependencies
└── README.md                     # This file
```

## Class Balancing

The system uses a 3-step Group-then-SMOTE pipeline:

```python
from src.model.balancing import apply_super_classes, get_balanced_data

# Step 1: Group micro-classes to Super-Classes
df_grouped = apply_super_classes(df)
# Output: 6 Super-Classes (BENIGN, DOS_ATTACK, WEB_ATTACK, BRUTE_FORCE, INFILTRATION_GENERAL, PortScan)

# Step 2: Apply SMOTE + RandomUnderSampler
df_balanced = get_balanced_data(df)
# Output: ~550k samples with balanced representation
```

**Key Features:**
- Pattern-based matching with `str.contains()` handles weird characters in labels
- Preserves rare attack semantics via Super-Class grouping
- SMOTE generates synthetic samples for minority classes
- Class weights in loss function further address imbalance

## Security Response

### Response Agent

Automated threat mitigation via the ResponseAgent:

```python
from src.agents.response_agent import ResponseAgent

# Model output with prediction and source IP
model_output = {'label': 'DOS_ATTACK', 'source_ip': '192.168.1.100'}
agent = ResponseAgent(model_output)
response = agent.generate_response()
# Output: {'status': 'Mitigated', 'action': 'iptables rule', 'summary': '...'}
```

### IP Blocking Tool

Manual IP blocking for threat response:

```python
from src.engine.tools import block_ip_tool

# Generate iptables blocking rule
result = block_ip_tool("192.168.1.100", "DOS_ATTACK")
# Logs action to security_actions.log
```

## Development

**Linting and Formatting:**

```bash
ruff check src/ app/
ruff format src/ app/
```

## License

MIT License
