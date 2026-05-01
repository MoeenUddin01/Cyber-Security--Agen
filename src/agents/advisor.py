"""Cyber Security AI Advisor using Groq API for threat analysis."""

import os
from typing import Dict, Any
from dotenv import load_dotenv

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    print("Warning: groq not installed. AI Advisor will be disabled.")


class SecurityAdvisor:
    """AI-powered cybersecurity threat advisor using Groq."""
    
    def __init__(self, api_key: str | None = None):
        """Initialize the security advisor with Groq.
        
        Args:
            api_key: Groq API key. If None, tries to get from .env file.
        """
        if not GROQ_AVAILABLE:
            raise ImportError("groq is required. Install with: pip install groq")
        
        # Load environment variables from .env file
        load_dotenv()
        
        # Get API key from parameter or environment
        self.api_key = api_key or os.getenv('GROQ_API_KEY')
        
        if not self.api_key:
            raise ValueError("Groq API key required. Set GROQ_API_KEY in .env file or pass api_key parameter.")
        
        # Initialize Groq client
        self.client = Groq(api_key=self.api_key)
        self.model = "llama-3.3-70b-versatile"
        
        print("🤖 SecurityAdvisor initialized with Groq AI")
    
    def get_advice(self, attack_type: str, confidence: str, features: Dict[str, Any]) -> str:
        """Get AI advice for detected cybersecurity threat.
        
        Args:
            attack_type: Type of attack detected (e.g., 'DOS_ATTACK', 'WEB_ATTACK')
            confidence: Confidence level of the detection (e.g., '85.52%')
            features: Dictionary of network features that triggered the detection
            
        Returns:
            AI-generated advice string explaining the attack and mitigation.
        """
        # Create the prompt for Groq
        prompt = self._create_advisor_prompt(attack_type, confidence, features)
        
        try:
            # Get response from Groq
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a Senior AI Security Operations Center (SOC) Analyst. Provide concise, actionable security advice."
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                max_tokens=100,
                temperature=0.3
            )
            
            advice = response.choices[0].message.content.strip()
            return advice
            
        except Exception as e:
            error_msg = f"AI Advisor Error: {str(e)}"
            print(f"⚠️ {error_msg}")
            return "Unable to generate AI advice at this time. Please check network connectivity and API key."
    
    def _create_advisor_prompt(self, attack_type: str, confidence: str, features: Dict[str, Any]) -> str:
        """Create a detailed prompt for Groq based on attack information.
        
        Args:
            attack_type: Type of attack detected
            confidence: Confidence level
            features: Network features
            
        Returns:
            Formatted prompt string for Groq
        """
        # Extract key metrics for the prompt
        port = features.get('Destination Port', 'Unknown')
        duration = features.get('Flow Duration', 0)
        fwd_packets = features.get('Total Fwd Packets', 0)
        bwd_packets = features.get('Total Bwd Packets', 0)
        fwd_length = features.get('Total Length of Fwd Packets', 0)
        flow_bytes_per_sec = features.get('Flow Bytes/s', 0)
        flow_packets_per_sec = features.get('Flow Packets/s', 0)
        
        prompt = f"""Explain what a {attack_type} is in one sentence. Then, explain why blocking the source IP is the correct immediate response. Keep the total response under 50 words.

Detection Details:
- Attack Type: {attack_type}
- Confidence: {confidence}
- Destination Port: {port}
- Flow Duration: {duration} microseconds
- Forward Packets: {fwd_packets}
- Backward Packets: {bwd_packets}
- Forward Data Volume: {fwd_length} bytes
- Flow Rate: {flow_bytes_per_sec} bytes/sec, {flow_packets_per_sec} packets/sec"""
        
        return prompt
    
    def get_attack_summary(self, attack_type: str) -> str:
        """Get a general summary of a specific attack type.
        
        Args:
            attack_type: Type of attack
            
        Returns:
            Brief explanation of the attack type.
        """
        prompt = f"""You are a cybersecurity expert. In one sentence, explain what a {attack_type} is and what it typically targets in a network."""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a Senior AI Security Operations Center (SOC) Analyst."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=50,
                temperature=0.3
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Unable to generate summary for {attack_type}"


# Example usage and testing
if __name__ == "__main__":
    # Test the advisor (requires API key)
    try:
        advisor = SecurityAdvisor()
        
        # Sample attack data
        attack_type = "DOS_ATTACK"
        confidence = "85.52%"
        features = {
            'Destination Port': 443,
            'Flow Duration': 1000000,
            'Total Fwd Packets': 50,
            'Total Bwd Packets': 50,
            'Total Length of Fwd Packets': 5000,
            'Flow Bytes/s': 10,
            'Flow Packets/s': 0.1
        }
        
        # Get AI advice
        advice = advisor.get_advice(attack_type, confidence, features)
        print(f"\n🤖 AI Security Advisor Analysis:")
        print(f"Attack: {attack_type} | Confidence: {confidence}")
        print(f"Advice: {advice}")
        
        # Get attack summary
        summary = advisor.get_attack_summary(attack_type)
        print(f"\n📋 Attack Summary: {summary}")
        
    except (ImportError, ValueError) as e:
        print(f"❌ Advisor initialization failed: {e}")
        print("To use the AI Advisor:")
        print("1. Install: pip install groq python-dotenv")
        print("2. Create .env file with: GROQ_API_KEY='your-groq-api-key'")
        print("3. Or pass API key directly: SecurityAdvisor(api_key='your-key')")
