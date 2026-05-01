"""Integrated Cyber Security Agent Monitor - The heart of the Agent system."""

import csv
import random
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import numpy as np

from src.model.prediction import ThreatPredictor
from src.engine.tools import block_ip_tool
from src.agents.advisor import SecurityAdvisor


class SecurityMonitor:
    """Integrated real-time cybersecurity threat monitoring system."""
    
    def __init__(self, data_path: str = "dataset/processed/balanced_dataset.csv"):
        """Initialize the security monitor.
        
        Args:
            data_path: Path to the balanced dataset for simulation.
        """
        # Initialize components
        self.predictor = ThreatPredictor()
        
        # Initialize AI Advisor (may fail if API key not available)
        try:
            self.advisor = SecurityAdvisor()
            print("🤖 AI Advisor initialized")
        except (ImportError, ValueError) as e:
            print(f"⚠️ AI Advisor unavailable: {e}")
            self.advisor = None
        
        self.data_path = Path(data_path)
        self.incident_log_path = Path("artifacts/incident_logs.csv")
        
        # Load data for simulation (50 random rows)
        self.load_simulation_data()
        
        # Initialize incident log
        self.init_incident_log()
        
        # Monitor statistics
        self.stats = {
            'total_packets': 0,
            'threats_detected': 0,
            'ips_blocked': 0,
            'start_time': datetime.now()
        }
    
    def load_simulation_data(self):
        """Load 50 random rows from dataset for simulation."""
        print("🔄 Loading simulation data...")
        df = pd.read_csv(self.data_path)
        
        # Sample 50 random rows
        df_sample = df.sample(n=50, random_state=42).reset_index(drop=True)
        
        # Exclude the label column, keep only features
        self.feature_columns = [col for col in df_sample.columns if col != 'Super_Label']
        self.simulation_data = df_sample[self.feature_columns].values
        
        print(f"✅ Loaded {len(self.simulation_data)} traffic samples for simulation")
        print(f"📊 Monitoring {len(self.feature_columns)} network features")
    
    def init_incident_log(self):
        """Initialize incident log CSV file."""
        self.incident_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create file with headers if it doesn't exist
        if not self.incident_log_path.exists():
            with open(self.incident_log_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'attack_type', 'confidence', 'threat_level', 'source_ip', 'ai_advice', 'features_summary'])
        
        print(f"📝 Incident log initialized: {self.incident_log_path}")
    
    def generate_fake_ip(self):
        """Generate a fake IP address for simulation."""
        return f"192.168.1.{random.randint(100, 254)}"
    
    def log_incident(self, prediction_result: dict, features: list, source_ip: str, ai_advice: str):
        """Log security incident to CSV file.
        
        Args:
            prediction_result: Result from ThreatPredictor
            features: Feature values that triggered the threat
            source_ip: Generated source IP
            ai_advice: AI-generated advice
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create features summary (first 5 features for brevity)
        features_summary = f"Port:{features[0]}, Duration:{features[1]:.0f}, Fwd_Pkts:{features[2]}, Bwd_Pkts:{features[3]}, Fwd_Len:{features[4]}"
        
        with open(self.incident_log_path, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                prediction_result['label'],
                prediction_result['confidence'],
                prediction_result['threat_level'],
                source_ip,
                ai_advice,
                features_summary
            ])
    
    def print_colored_alert(self, prediction_result: dict, features: list, source_ip: str, ai_advice: str, block_result: dict):
        """Print high-visibility security alert with colored output.
        
        Args:
            prediction_result: Result from ThreatPredictor
            features: Feature values that triggered the threat
            source_ip: Generated source IP
            ai_advice: AI-generated advice
            block_result: Result from IP blocking tool
        """
        # Red alert
        alert = f"\033[91m🚨🚨🚨 THREAT DETECTED 🚨🚨🚨\033[0m"
        alert += f"\n\033[91m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        alert += f"\n\033[91m⚠️  ATTACK TYPE: {prediction_result['label']}\033[0m"
        alert += f"\n\033[91m📈  CONFIDENCE: {prediction_result['confidence']}\033[0m"
        alert += f"\n\033[91m🔥  THREAT LEVEL: {prediction_result['threat_level']}\033[0m"
        alert += f"\n\033[91m⏰  TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m"
        alert += f"\n\033[91m🌐 SOURCE IP: {source_ip}\033[0m"
        alert += f"\n\033[91m📊  TRAFFIC SUMMARY: Port:{features[0]}, Duration:{features[1]:.0f}, Fwd_Pkts:{features[2]}\033[0m"
        alert += f"\n\033[91m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        
        # Cyan AI advice
        if ai_advice:
            alert += f"\n\033[96m🤖 AI ANALYSIS:\033[0m"
            alert += f"\n\033[96m{ai_advice}\033[0m"
        
        # Green action
        alert += f"\n\033[92m🛡️  MITIGATION ACTION:\033[0m"
        alert += f"\n\033[92m✅ IP {source_ip} blocked successfully\033[0m"
        alert += f"\n\033[92m� Incident logged to {self.incident_log_path}\033[0m"
        alert += f"\n\033[92m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
        
        print(alert)
    
    def process_traffic_sample(self, features: list):
        """Process a single traffic sample for threat detection.
        
        Args:
            features: List of 17 feature values
        """
        self.stats['total_packets'] += 1
        
        # Run threat prediction
        result = self.predictor.predict(features)
        
        if result['is_threat']:
            # Threat detected!
            self.stats['threats_detected'] += 1
            
            # Generate fake IP
            source_ip = self.generate_fake_ip()
            
            # Block the IP
            block_result = block_ip_tool(source_ip, result['label'])
            self.stats['ips_blocked'] += 1
            
            # Get AI advice
            ai_advice = ""
            if self.advisor:
                try:
                    # Convert features to dict for advisor
                    feature_dict = {
                        'Destination Port': features[0],
                        'Flow Duration': features[1],
                        'Total Fwd Packets': features[2],
                        'Total Bwd Packets': features[3],
                        'Total Length of Fwd Packets': features[4],
                        'Flow Bytes/s': features[11],
                        'Flow Packets/s': features[12]
                    }
                    ai_advice = self.advisor.get_advice(result['label'], result['confidence'], feature_dict)
                except Exception as e:
                    ai_advice = f"AI Advisor Error: {str(e)}"
            else:
                ai_advice = "AI Advisor unavailable - using rule-based mitigation"
            
            # Print colored alert
            self.print_colored_alert(result, features, source_ip, ai_advice, block_result)
            
            # Log incident
            self.log_incident(result, features, source_ip, ai_advice)
        else:
            # System healthy - occasional heartbeat
            if self.stats['total_packets'] % 10 == 0:
                print(f"💚 System Healthy | Packets processed: {self.stats['total_packets']} | Threats blocked: {self.stats['threats_detected']}")
    
    def run_monitoring_loop(self, delay_seconds: float = 2.0):
        """Run continuous security monitoring loop.
        
        Args:
            delay_seconds: Delay between processing packets
        """
        print(f"\n🛡️  INTEGRATED CYBER SECURITY AGENT MONITORING STARTED")
        print(f"📡 Monitoring {len(self.simulation_data)} traffic samples...")
        print(f"⚡ Processing delay: {delay_seconds}s per packet")
        print(f"🔍 Press Ctrl+C to stop monitoring\n")
        
        try:
            while True:
                # Pick random traffic sample
                random_idx = random.randint(0, len(self.simulation_data) - 1)
                traffic_sample = self.simulation_data[random_idx].tolist()
                
                # Process the sample
                self.process_traffic_sample(traffic_sample)
                
                # Delay for realistic simulation
                time.sleep(delay_seconds)
                
        except KeyboardInterrupt:
            self.print_monitoring_summary()
            print("\n🛑 Monitoring stopped by user")
    
    def print_monitoring_summary(self):
        """Print monitoring session summary."""
        runtime = datetime.now() - self.stats['start_time']
        
        summary = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 INTEGRATED MONITORING SESSION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⏱️  Runtime: {runtime}
📦 Total Packets: {self.stats['total_packets']}
🚨 Threats Detected: {self.stats['threats_detected']}
🛡️  IPs Blocked: {self.stats['ips_blocked']}
📈 Detection Rate: {(self.stats['threats_detected']/self.stats['total_packets']*100):.2f}%
📝 Incident Log: {self.incident_log_path}
🤖 AI Advisor: {'Available' if self.advisor else 'Unavailable'}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        print(summary)


if __name__ == "__main__":
    # Start the integrated security monitor
    monitor = SecurityMonitor()
    
    # Run monitoring with 2-second delay for demo
    monitor.run_monitoring_loop(delay_seconds=2.0)
