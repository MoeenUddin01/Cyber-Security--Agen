"""Test script for the FastAPI cybersecurity API."""

import requests
import json

def test_api():
    """Test the FastAPI API endpoints."""
    base_url = "http://localhost:8000"
    
    # Test health endpoint
    try:
        response = requests.get(f"{base_url}/health")
        print("✅ Health check:", response.json())
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return
    
    # Test analyze endpoint with sample data
    sample_data = {
        "features": [
            443,  # Destination Port
            1000000,  # Flow Duration
            50,  # Total Fwd Packets
            50,  # Total Bwd Packets
            5000,  # Total Length of Fwd Packets
            3000,  # Total Length of Bwd Packets
            200,  # Fwd Packet Length Max
            50,  # Fwd Packet Length Min
            100,  # Fwd Packet Length Mean
            150,  # Bwd Packet Length Max
            30,  # Bwd Packet Length Min
            60,  # Bwd Packet Length Mean
            10,  # Flow Bytes/s
            0.1,  # Flow Packets/s
            50000,  # Flow IAT Mean
            10000,  # Flow IAT Std
            100000  # Flow IAT Max
        ],
        "source_ip": "192.168.1.100"
    }
    
    try:
        response = requests.post(f"{base_url}/analyze", json=sample_data)
        print("✅ Analysis result:")
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"❌ Analysis failed: {e}")

if __name__ == "__main__":
    print("Testing Cybersecurity Threat Detection API...")
    print("Make sure the API is running with: python -m uvicorn app.main:app --reload")
    test_api()
