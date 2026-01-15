import sqlite3
import pandas as pd
from sklearn.ensemble import IsolationForest
DB_FILE = "netguard.db"
def train_and_detect():
    # 1. Load Data
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql("SELECT * FROM traffic", conn)
    conn.close()
    # 2. Feature Engineering (Preparing Data for AI)
    # AI only understands numbers. We need to convert text to numbers.
    # We will use 'length' (already a number) and 'protocol' (needs conversion).
    
    # Simple conversion: TCP=1, UDP=2, Other=0
    df['protocol_num'] = df['protocol'].map({'TCP': 1, 'UDP': 2}).fillna(0)
    
    # We select the features we want the AI to learn from
    features = df[['length', 'protocol_num']]
    print("--- Training AI Model ---")
    # 3. Train the Model
    # contamination=0.01 means "We expect about 1% of traffic to be bad"
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(features)
    # 4. Predict
    # The model gives each packet a score: 1 (Normal), -1 (Anomaly)
    df['anomaly'] = model.predict(features)
    # 5. Show Results
    anomalies = df[df['anomaly'] == -1]
    
    print(f"Total Packets: {len(df)}")
    print(f"Anomalies Detected: {len(anomalies)}")
    
    if len(anomalies) > 0:
        print("\n--- Suspicious Packets Found! ---")
        print(anomalies[['src_ip', 'dst_ip', 'protocol', 'length']])
    else:
        print("\nNo anomalies found. Your network looks normal.")
if __name__ == "__main__":
    train_and_detect()