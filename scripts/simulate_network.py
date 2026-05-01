from src.model.prediction import ThreatPredictor

# Initialize the Brain
predictor = ThreatPredictor()

# --- SCENARIO 1: Standard Web Browsing (Benign) ---
# Normal port, low packet count, small window sizes
benign_traffic = [80, 5000, 2, 2, 100, 50, 50, 0, 50, 50, 0, 20000, 400, 2500, 5000, 255, 255]

# --- SCENARIO 2: DoS Attack (Malicious) ---
# High packet count, massive forward length, huge Init_Win_bytes
dos_attack = [443, 1000000, 50, 50, 5000, 1000, 500, 200, 1000, 500, 200, 10, 0.1, 20000, 50000, 29200, 29200]

print("--- 🛡️ CYBER SECURITY AGENT: LIVE INFERENCE TEST ---")

print(f"\n[Test 1] Simulating Normal Traffic...")
res1 = predictor.predict(benign_traffic)
print(f"Result: {res1['label']} | Confidence: {res1['confidence']} | Threat: {res1['is_threat']}")

print(f"\n[Test 2] Simulating DoS Attack...")
res2 = predictor.predict(dos_attack)
print(f"Result: {res2['label']} | Confidence: {res2['confidence']} | Threat: {res2['is_threat']}")

if res2['is_threat']:
    print("\n🚨 ALERT: Mitigation Agent triggered! Blocking source IP...")
