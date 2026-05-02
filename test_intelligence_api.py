"""Test script for the enhanced FastAPI API with IP intelligence."""

import requests
import json

def test_intelligence_api():
    """Test the FastAPI API with IP intelligence integration."""
    base_url = "http://localhost:8000"
    
    # Test health endpoint
    try:
        response = requests.get(f"{base_url}/health")
        print("✅ Health check:", response.json())
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return
    
    # Test analyze endpoint with sample data and IP
    sample_data = {
        "features": [
            443, 1000000, 50, 50, 5000, 3000, 200, 50, 100, 150, 30, 60, 10, 0.1, 50000, 10000, 100000
        ],
        "source_ip": "8.8.8.8"  # Google's public DNS for testing
    }
    
    try:
        response = requests.post(f"{base_url}/analyze", json=sample_data)
        print("✅ Analysis result with IP intelligence:")
        print(json.dumps(response.json(), indent=2))
        
        # Check if IP intelligence is included
        result = response.json()
        if "ip_intel" in result:
            print("\n🔍 IP Intelligence Data:")
            intel = result["ip_intel"]
            print(f"Provider: {intel.get('provider', 'Unknown')}")
            print(f"Country: {intel.get('country', 'Unknown')}")
            print(f"Open Services: {intel.get('open_services', [])}")
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")

if __name__ == "__main__":
    print("Testing Cybersecurity Threat Detection API with IP Intelligence...")
    print("Make sure the API is running with: uv run python -m uvicorn app.main:app --reload")
    test_intelligence_api()
