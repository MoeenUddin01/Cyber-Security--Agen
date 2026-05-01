import torch
import joblib
import numpy as np
from src.model.model import IDS_Model

class ThreatPredictor:
    def __init__(self, model_path='artifacts/best_model.pth', 
                 scaler_path='artifacts/scaler.joblib', 
                 encoder_path='artifacts/label_encoder.joblib'):
        
        self.device = torch.device('cpu')
        
        # 1. Load Artifacts
        self.scaler = joblib.load(scaler_path)
        self.encoder = joblib.load(encoder_path)
        
        # 2. Initialize & Load Model
        self.model = IDS_Model(input_size=17, num_classes=len(self.encoder.classes_))
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.eval()
        
    def predict(self, feature_list):
        """Expects a list of 17 features in the correct order."""
        # Preprocess
        features_scaled = self.scaler.transform([feature_list])
        features_tensor = torch.FloatTensor(features_scaled).to(self.device)
        
        # Inference
        with torch.no_grad():
            output = self.model(features_tensor)
            probabilities = torch.exp(output) # Get actual probabilities
            conf, pred_idx = torch.max(probabilities, 1)
        
        label = self.encoder.inverse_transform([pred_idx.item()])[0]
        confidence = conf.item()
        
        return {
            "label": label,
            "confidence": f"{confidence:.2%}",
            "is_threat": label != 'BENIGN',
            "threat_level": "HIGH" if label != 'BENIGN' and confidence > 0.8 else "LOW"
        }