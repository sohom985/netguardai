"""
test_ml.py - Test the ML Anomaly Detection with REAL data
Run this file to see ML in action!
"""
import sqlite3
import pandas as pd
from ml_detector import train_model, predict

print("=" * 50)
print("🧠 ML Anomaly Detection Test")
print("=" * 50)

# Step 1: Load real data from your database
print("\n📡 Loading data from netguard.db...")
conn = sqlite3.connect('netguard.db')
df = pd.read_sql('SELECT * FROM traffic LIMIT 1000', conn)
conn.close()

print(f"✅ Loaded {len(df)} real packets")

# Step 2: Train the model
print("\n🏋️ Training Isolation Forest model...")
train_model(df)

# Step 3: Make predictions
print("\n🔮 Making predictions...")
result = predict(df)

# Step 4: Show results
anomalies = result[result['ml_prediction'] == '🔴 Anomaly']
normal = result[result['ml_prediction'] == '🟢 Normal']

print(f"\n📊 Results:")
print(f"   🟢 Normal packets: {len(normal)}")
print(f"   🔴 Anomalies found: {len(anomalies)}")

if len(anomalies) > 0:
    print("\n🚨 Top 5 Anomalies:")
    print(anomalies[['timestamp', 'src_ip', 'length', 'anomaly_score']].head(5).to_string())
else:
    print("\n✅ No anomalies detected in this batch!")

print("\n" + "=" * 50)
print("Test complete!")
