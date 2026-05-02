"""FastAPI application for cybersecurity threat detection and analysis."""

from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from jinja2 import Environment, FileSystemLoader
import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.model.prediction import ThreatPredictor
from src.agents.advisor import SecurityAdvisor
from src.agent.interrogator import interrogate_ip
from src.engine.tools import block_ip_tool


# Expanded Library: 3 samples per category
TEST_SAMPLES = {
    # --- BENIGN TRAFFIC ---
    "Benign: Standard Browsing": {"features": [80, 5000, 2, 2, 100, 50, 50, 0, 50, 50, 0, 20000, 400, 2500, 5000, 255, 255], "source_ip": "192.168.1.10"},
    "Benign: Large File Download": {"features": [443, 5000000, 100, 150, 50000, 80000, 500, 10, 800, 500, 10, 1000, 200, 500, 1000, 512, 512], "source_ip": "192.168.1.11"},
    "Benign: Video Streaming": {"features": [443, 2000000, 50, 80, 25000, 40000, 500, 20, 500, 500, 0, 5000, 300, 800, 2000, 255, 255], "source_ip": "192.168.1.12"},

    # --- DOS ATTACKS ---
    "DoS: TCP SYN Flood": {"features": [80, 1000000, 50, 0, 0, 0, 0, 0, 0, 0, 0, 50, 0, 0, 0, 1024, 0], "source_ip": "185.156.177.42"},
    "DoS: Slowloris (Low/Slow)": {"features": [80, 15000000, 10, 5, 500, 200, 50, 10, 40, 40, 0, 1, 0.1, 50, 100, 255, 255], "source_ip": "45.33.2.145"},
    "DoS: High Velocity UDP": {"features": [53, 500000, 200, 200, 20000, 20000, 100, 0, 100, 100, 0, 800, 400, 100, 100, 0, 0], "source_ip": "103.212.69.5"},

    # --- BRUTE FORCE ---
    "Brute Force: SSH Password Crack": {"features": [22, 10000, 20, 20, 1500, 1500, 75, 75, 75, 75, 0, 4000, 2000, 100, 500, 255, 255], "source_ip": "190.115.18.2"},
    "Brute Force: FTP Guessing": {"features": [21, 5000, 15, 15, 1000, 1000, 60, 60, 60, 60, 0, 6000, 3000, 100, 300, 255, 255], "source_ip": "172.217.16.142"},
    "Brute Force: Web Admin Panel": {"features": [80, 8000, 25, 25, 2000, 2000, 80, 80, 80, 80, 0, 6250, 3125, 150, 400, 255, 255], "source_ip": "185.176.27.10"},

    # --- PORT SCAN ---
    "Port Scan: Nmap Stealth SYN": {"features": [0, 100, 1, 0, 0, 0, 0, 0, 0, 0, 0, 10000, 100, 0, 0, 1024, 0], "source_ip": "5.188.62.75"},
    "Port Scan: Fast Comprehensive": {"features": [0, 500, 10, 0, 0, 0, 0, 0, 0, 0, 0, 20000, 1000, 0, 0, 512, 0], "source_ip": "91.241.19.12"},
    "Port Scan: Slow FIN Scan": {"features": [0, 5000, 5, 0, 0, 0, 0, 0, 0, 0, 0, 1000, 50, 0, 0, 255, 0], "source_ip": "141.98.10.21"}
}


class NetworkData(BaseModel):
    """Pydantic model for network data input."""
    features: List[float] = Field(..., min_items=17, max_items=17, description="List of 17 network features")
    source_ip: Optional[str] = Field(None, description="Source IP address (optional)")


# Initialize FastAPI app
app = FastAPI(
    title="CyberShield AI - Threat Detection API",
    description="Advanced AI-powered cybersecurity threat detection and mitigation system",
    version="2.0.0"
)

# Get absolute paths
BASE_DIR = Path(__file__).resolve().parent
static_dir = BASE_DIR / "static"
templates_dir = BASE_DIR / "templates"

# Mount static files
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Initialize Jinja2 environment
jinja_env = Environment(loader=FileSystemLoader(str(templates_dir)))

# Initialize components
try:
    predictor = ThreatPredictor()
    print("✅ ThreatPredictor initialized successfully")
except Exception as e:
    print(f"❌ Failed to initialize ThreatPredictor: {e}")
    predictor = None

try:
    advisor = SecurityAdvisor()
    print("✅ SecurityAdvisor initialized successfully")
except Exception as e:
    print(f"❌ Failed to initialize SecurityAdvisor: {e}")
    advisor = None


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Serve the main dashboard page."""
    template = jinja_env.get_template("index.html")
    return template.render(request=request)


@app.post("/analyze")
async def analyze_network_data(data: NetworkData):
    """
    Analyze network data for cybersecurity threats.
    
    Args:
        data: NetworkData containing features and optional source_ip
        
    Returns:
        JSON response with prediction, AI advice, and mitigation status
    """
    if not predictor:
        raise HTTPException(status_code=503, detail="ThreatPredictor not available")
    
    try:
        # Get prediction
        prediction = predictor.predict(data.features)
        
        # Initialize response
        response = {
            "prediction": prediction,
            "ai_advice": None,
            "mitigation_status": None
        }
        
        # If threat is detected, get IP intelligence, AI advice and perform mitigation
        if prediction["is_threat"]:
            # Get IP intelligence if source IP is provided
            ip_intel = None
            if data.source_ip:
                try:
                    ip_intel = interrogate_ip(data.source_ip)
                except Exception as e:
                    print(f"IP interrogation failed for {data.source_ip}: {e}")
                    ip_intel = {"provider": "Unknown", "country": "Unknown", "open_services": []}
            
            # Get AI advice
            if advisor:
                try:
                    # Create features dict for advisor
                    feature_names = [
                        'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Bwd Packets',
                        'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
                        'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Bwd Packet Length Max',
                        'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Flow Bytes/s', 'Flow Packets/s',
                        'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max'
                    ]
                    features_dict = dict(zip(feature_names, data.features))
                    
                    advice = advisor.get_advice(
                        attack_type=prediction["label"],
                        confidence=prediction["confidence"],
                        features=features_dict,
                        intel=ip_intel
                    )
                    response["ai_advice"] = advice
                    response["ip_intel"] = ip_intel
                except Exception as e:
                    response["ai_advice"] = f"AI Advisor error: {str(e)}"
                    response["ip_intel"] = ip_intel
            else:
                response["ai_advice"] = "AI Advisor not available"
                response["ip_intel"] = ip_intel
            
            # Perform IP blocking if source_ip is provided
            if data.source_ip:
                try:
                    mitigation_result = block_ip_tool(
                        ip_address=data.source_ip,
                        attack_type=prediction["label"]
                    )
                    response["mitigation_status"] = {
                        "blocked": True,
                        "ip": data.source_ip,
                        "action": mitigation_result
                    }
                except Exception as e:
                    response["mitigation_status"] = {
                        "blocked": False,
                        "ip": data.source_ip,
                        "error": str(e)
                    }
            else:
                response["mitigation_status"] = {
                    "blocked": False,
                    "ip": None,
                    "reason": "No source IP provided for blocking"
                }
        else:
            response["ai_advice"] = "No threat detected"
            response["mitigation_status"] = {
                "blocked": False,
                "reason": "Benign traffic, no mitigation needed"
            }
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "predictor_available": predictor is not None,
        "advisor_available": advisor is not None
    }


@app.get("/samples")
async def get_test_samples():
    """Get pre-defined test samples for easy API testing."""
    return {
        "description": "Pre-defined attack patterns for testing the API",
        "samples": TEST_SAMPLES
    }


@app.get("/test-scenarios")
async def get_scenarios():
    """Returns the list of all available attack names for the UI."""
    return list(TEST_SAMPLES.keys())


@app.post("/test-scenario/{scenario_name}")
async def run_test_scenario(scenario_name: str):
    """
    Pick an attack scenario from the library and run a full Guardian loop.
    Available: benign_web_browsing, dos_flooding_attack, brute_force_ssh, port_scan_recon
    """
    if scenario_name not in TEST_SAMPLES:
        raise HTTPException(status_code=404, detail="Scenario not found in library")
    
    # Extract pre-stored data
    sample = TEST_SAMPLES[scenario_name]
    
    # Wrap it in our existing logic (same as /analyze)
    data = NetworkData(features=sample["features"], source_ip=sample["source_ip"])
    return await analyze_network_data(data)  # Re-uses main logic you already built!


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
