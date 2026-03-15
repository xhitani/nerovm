import time, sys
sys.path.insert(0, '/home/nero/nero')

print("=" * 50)
print("  NERO FEATURE TEST REPORT")
print("=" * 50)

# Test 1: imports
try:
    from nero import (devices, trust_scores, dna_store,
                      anomaly_models, mac_history,
                      calculate_trust, get_dna_summary,
                      send_telegram, trust_label, trust_emoji)
    print("✅ TEST 1: All modules import correctly")
except Exception as e:
    print(f"❌ TEST 1: Import failed — {e}")

# Test 2: trust scoring logic
try:
    from nero import devices, trust_scores, mac_history
    from collections import defaultdict
    import nero
    nero.devices = {"192.168.1.99": {"ip":"192.168.1.99","mac":"aa:bb:cc:dd:ee:99","visits":5,"first_seen":time.time(),"last_seen":time.time(),"name":"test"}}
    nero.mac_history["192.168.1.99"].add("aa:bb:cc:dd:ee:99")
    nero.arp_timestamps["192.168.1.99"] = [time.time()-i for i in range(10)]
    score = calculate_trust("192.168.1.99")
    print(f"✅ TEST 2: Trust scoring works — score: {score}/100 ({trust_label(score)})")
except Exception as e:
    print(f"❌ TEST 2: Trust scoring failed — {e}")

# Test 3: DNA vector
try:
    vec = nero.extract_dna_vector("192.168.1.99")
    if vec:
        print(f"✅ TEST 3: DNA fingerprinting works — vector: {[round(v,1) for v in vec]}")
    else:
        print("⚠️  TEST 3: DNA needs more data — run for longer")
except Exception as e:
    print(f"❌ TEST 3: DNA failed — {e}")

# Test 4: anomaly model
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    X = np.random.rand(20, 6)
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)
    pred = model.predict([X[0]])[0]
    print(f"✅ TEST 4: AI model works — prediction: {'normal' if pred==1 else 'anomaly'}")
except Exception as e:
    print(f"❌ TEST 4: AI model failed — {e}")

# Test 5: scapy
try:
    from scapy.all import ARP, Ether
    pkt = Ether() / ARP()
    print(f"✅ TEST 5: Scapy works — ARP packet created")
except Exception as e:
    print(f"❌ TEST 5: Scapy failed — {e}")

# Test 6: flask
try:
    from flask import Flask
    app = Flask(__name__)
    print(f"✅ TEST 6: Flask works — dashboard ready")
except Exception as e:
    print(f"❌ TEST 6: Flask failed — {e}")

# Test 7: telegram config
try:
    import nero
    if nero.TELEGRAM_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print(f"⚠️  TEST 7: Telegram not configured yet — add your token")
    else:
        print(f"✅ TEST 7: Telegram token configured")
except Exception as e:
    print(f"❌ TEST 7: Telegram check failed — {e}")

print("=" * 50)
print("  Done! Fix any ❌ before running NERO for real.")
print("=" * 50)
