"""FastAPI application for cybersecurity threat detection and analysis."""

from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.model.prediction import ThreatPredictor
from src.agents.advisor import SecurityAdvisor
from src.engine.tools import block_ip_tool


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

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

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


@app.get("/")
async def root(request: Request):
    """Serve the main dashboard page."""
    return templates.TemplateResponse("index.html", {"request": request})


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
        
        # If threat is detected, get AI advice and perform mitigation
        if prediction["is_threat"]:
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
                        features=features_dict
                    )
                    response["ai_advice"] = advice
                except Exception as e:
                    response["ai_advice"] = f"AI Advisor error: {str(e)}"
            else:
                response["ai_advice"] = "AI Advisor not available"
            
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
