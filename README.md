# Cybersecurity Intrusion Detection System

A deep learning-based network intrusion detection system using the CIC-IDS2017 dataset. This project implements feature pruning, Super-Class grouping, SMOTE balancing, model training with artifact persistence, and automated security response capabilities.

## Overview

This system detects network attacks using a neural network trained on network flow features. It includes:

- **Data Preprocessing**: Feature pruning from 78 to 17 golden features
- **Super-Class Grouping**: Maps 15 micro-classes to 6 attack categories
- **Class Balancing**: SMOTE + RandomUnderSampler for handling imbalance
- **Model Training**: 4-layer MLP (IDS_Model) with BatchNorm, Dropout, and NLLLoss
- **Artifact Persistence**: Saves scaler, encoder, model weights, and metrics to `artifacts/`
- **Evaluation**: Classification reports and confusion matrix visualization
- **Security Response**: Automated IP blocking via ResponseAgent

## Dataset

**CIC-IDS2017** - Network intrusion detection dataset containing:
- 2.8M+ network flow records
- 15 attack types including DDoS, PortScan, Web Attacks, Botnet, etc.
- 78 original features pruned to 17 golden features

Raw data location: `dataset/raw/`
Processed data: `dataset/processed/balanced_dataset.csv`

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

## Configuration

The project uses `config.yaml` for centralized configuration management:

```yaml
# Key configuration sections
paths:
  project_root: "."
  balanced_dataset: "dataset/processed/balanced_dataset.csv"
  artifacts_dir: "artifacts"

data:
  batch_size: 1024
  test_size: 0.2
  random_state: 42

model:
  input_size: 17
  num_classes: 6
  architecture:
    hidden_layers: [256, 256, 64]
    dropout_rate: 0.3

training:
  epochs: 50
  learning_rate: 0.001
  device: "auto"  # auto, cuda, cpu
```

**Benefits:**
- **Centralized settings** - All parameters in one place
- **Easy tuning** - Modify hyperparameters without code changes
- **Version control** - Track configuration changes
- **Reproducibility** - Same config = same results

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

This creates `dataset/processed/balanced_dataset.csv` with 18 columns (17 features + Super_Label).

**Note:** Requires raw CIC-IDS2017 CSV files in `dataset/raw/` directory.

### Model Training

#### Configuration-Driven Pipeline

The new training pipeline uses `config.yaml` for all parameters:

```bash
python3 -m src.pipelines.model_training
```

**Features:**
- **Configuration-driven**: All settings in `config.yaml` (paths, hyperparameters, model architecture)
- **King of the Hill**: Automatically saves best performing model during training
- **Comprehensive logging**: Shows both training and test accuracy per epoch
- **Artifact persistence**: Saves scaler, encoder, model weights, and metrics
- **CPU fallback**: Handles GPU compatibility issues automatically

**Training Output:**
```
Epoch [X/50] | Train Loss: 0.XXX | Train Acc: XX.X% | Test Loss: 0.XXX | Test Acc: XX.X%
🌟 NEW BEST MODEL SAVED! | Accuracy: XX.X% | Path: artifacts/best_model.pth
```

#### Legacy Training Script

Direct training script (deprecated, use pipeline instead):

```bash
python src/model/train.py
```

**Note:** Both methods expect preprocessed data in `dataset/processed/balanced_dataset.csv`.

**Model Architecture:**
- **IDS_Model**: 4-layer MLP (17 → 256 → 256 → 64 → 6)
- Batch normalization and dropout for regularization
- NLLLoss with log_softmax output
- 80/20 train/test split with stratification

**Artifacts saved to `artifacts/`:**
- `best_model.pth` - **King of the Hill** best model weights (auto-saved)
- `ids_agent_model.pth` - Final model state dict
- `scaler.joblib` - Fitted StandardScaler for inference
- `label_encoder.joblib` - Fitted LabelEncoder for class names
- `metrics.json` - Complete training history (train/test loss & accuracy)
- `confusion_matrix.png` - Visualization of test results

### Model Evaluation

Evaluate the trained model and generate performance metrics:

```python
from src.model.evaluation import evaluate_model

# Load model, test_loader, device, and label_encoder
test_report = evaluate_model(model, test_loader, device, label_encoder)
```

**Features:**
- Classification report with per-class precision/recall/F1
- Confusion matrix heatmap visualization
- Saved to `artifacts/confusion_matrix.png`

## Project Structure

```
cyber_security/
├── app/                          # FastAPI web application
│   ├── main.py                   # FastAPI application entry point
│   ├── templates/                # HTML templates (Jinja2)
│   │   └── index.html            # Main dashboard UI
│   └── static/                   # Static assets
│       ├── css/                  # Stylesheets
│       │   └── style.css         # Custom CSS
│       └── js/                   # JavaScript
│           └── app.js            # Frontend logic
├── src/                          # Core library
│   ├── data/
│   │   ├── preprocessing.py      # Feature pruning and data cleaning
│   │   ├── loader.py             # Data loading with preprocessing
│   │   └── dataset.py            # PyTorch dataset classes (placeholder)
│   ├── model/
│   │   ├── model.py              # IDS_Model neural network
│   │   ├── prediction.py         # Threat predictor for inference
│   │   ├── train.py              # Training loop with artifact persistence
│   │   ├── evaluation.py         # Classification report & confusion matrix
│   │   └── balancing.py          # Super-Class grouping & SMOTE
│   ├── agents/
│   │   ├── advisor.py            # AI security advisor (Groq)
│   │   ├── monitor.py            # System monitoring agent
│   │   └── response_agent.py     # Automated response agent
│   ├── engine/
│   │   └── tools.py              # Security response tools (IP blocking)
│   ├── pipelines/
│   │   └── model_training.py     # Configuration-driven training pipeline
│   └── utils.py                  # Shared utilities
├── scripts/
│   ├── run_preprocessing_pipeline.py  # Full preprocessing pipeline
│   └── train.py                  # Model training script
├── dataset/
│   ├── raw/                      # Original CIC-IDS2017 CSV files
│   └── processed/                # Cleaned, merged, and balanced data
├── artifacts/                    # Saved models and metrics
├── notebook/                     # Jupyter notebooks for experiments
├── config.yaml                   # Configuration file
├── main.py                       # Entry point
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
- Saves balanced dataset to `dataset/processed/balanced_dataset.csv`

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

## FastAPI Web Interface

The project includes a **creative and modern FastAPI web interface** for real-time threat detection with an interactive dashboard.

### Features

- **🎨 Modern Dark Theme UI** - Beautiful gradient design with Tailwind CSS
- **📊 Interactive Dashboard** - Real-time threat visualization with Chart.js
- **🔍 Network Analysis** - Web form for entering 17 network features
- **🤖 AI-Powered Advice** - Groq AI integration for security recommendations
- **🛡️ Automated Mitigation** - IP blocking and threat response
- **📱 Responsive Design** - Works on desktop and mobile devices

### Running the Web Interface

```bash
# Start the FastAPI server
uv run python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Then open your browser to: **http://localhost:8000**

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard (HTML UI) |
| `/analyze` | POST | Analyze network data for threats |
| `/health` | GET | System health check |
| `/docs` | GET | Swagger API documentation |
| `/redoc` | GET | ReDoc API documentation |

### API Usage Example

```bash
# Analyze network traffic
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "features": [443, 1000000, 50, 50, 5000, 3000, 200, 50, 100, 150, 30, 60, 10, 0.1, 50000, 10000, 100000],
    "source_ip": "192.168.1.100"
  }'
```

**Response:**
```json
{
  "prediction": {
    "label": "DOS_ATTACK",
    "confidence": "85.52%",
    "is_threat": true,
    "threat_level": "HIGH"
  },
  "ai_advice": "A DOS_ATTACK floods your network with traffic to disrupt services...",
  "mitigation_status": {
    "blocked": true,
    "ip": "192.168.1.100",
    "action": "Successfully generated mitigation rule: sudo iptables -A INPUT -s 192.168.1.100 -j DROP"
  }
}
```

## Quick Start

```bash
# 1. Setup environment
python -m venv .venv
source .venv/bin/activate
uv sync

# 2. Preprocess data (requires raw CIC-IDS2017 files in dataset/raw/)
python scripts/run_preprocessing_pipeline.py

# 3. Train model using new pipeline
python3 -m src.pipelines.model_training

# 4. Start the web interface
uv run python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 5. Check artifacts
ls artifacts/
# best_model.pth  ids_agent_model.pth  scaler.joblib
# label_encoder.joblib  metrics.json  confusion_matrix.png
```

**Training Features:**
- 🌟 **King of the Hill** - Auto-saves best model during training
- 📊 **Dual metrics** - Tracks both training and test accuracy
- ⚙️ **Config-driven** - All settings in `config.yaml`
- 🔄 **CPU fallback** - Handles GPU compatibility automatically

## Development

**Linting and Formatting:**

```bash
ruff check src/ app/
ruff format src/ app/
```

## License

MIT License
