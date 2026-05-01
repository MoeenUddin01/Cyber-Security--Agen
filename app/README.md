# Cybersecurity Threat Detection API

FastAPI application for detecting and mitigating cybersecurity threats using machine learning and AI.

## Features

- **Threat Detection**: Uses trained ML model to detect network threats
- **AI Analysis**: Provides AI-powered security advice using Groq
- **Automated Mitigation**: Automatically blocks malicious IP addresses
- **Real-time Analysis**: Processes network data in real-time

## Setup

1. Ensure you have the required dependencies:
```bash
uv sync
```

2. Make sure you have model artifacts in `artifacts/` directory:
- `best_model.pth`
- `scaler.joblib`
- `label_encoder.joblib`

3. Set up your Groq API key in `.env` file:
```
GROQ_API_KEY=your-groq-api-key-here
```

## Running the API

Start the FastAPI server:
```bash
python -m uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`

## API Endpoints

### `GET /`
Root endpoint - returns API status

### `GET /health`
Health check - returns component availability

### `POST /analyze`
Main analysis endpoint

**Request Body:**
```json
{
    "features": [list of 17 float values],
    "source_ip": "optional source IP address"
}
```

**Response:**
```json
{
    "prediction": {
        "label": "threat_type",
        "confidence": "85.52%",
        "is_threat": true,
        "threat_level": "HIGH"
    },
    "ai_advice": "AI-generated security advice",
    "mitigation_status": {
        "blocked": true,
        "ip": "192.168.1.100",
        "action": "Successfully generated mitigation rule: sudo iptables -A INPUT -s 192.168.1.100 -j DROP"
    }
}
```

## Testing

Run the test script:
```bash
python test_api.py
```

## Network Features

The API expects exactly 17 network features in this order:
1. Destination Port
2. Flow Duration
3. Total Fwd Packets
4. Total Bwd Packets
5. Total Length of Fwd Packets
6. Total Length of Bwd Packets
7. Fwd Packet Length Max
8. Fwd Packet Length Min
9. Fwd Packet Length Mean
10. Bwd Packet Length Max
11. Bwd Packet Length Min
12. Bwd Packet Length Mean
13. Flow Bytes/s
14. Flow Packets/s
15. Flow IAT Mean
16. Flow IAT Std
17. Flow IAT Max

## API Documentation

Once the server is running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
