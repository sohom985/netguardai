"""
train_ultimate.py - Ultimate Training on 500K+ Samples
Maximum dataset size for production-grade model.
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os
import time
import warnings
warnings.filterwarnings('ignore')

print("=" * 70)
print("🚀 NetGuardAI - ULTIMATE Training (500,000 samples)")
print("=" * 70)

DATA_DIR = "datasets"
os.makedirs(DATA_DIR, exist_ok=True)

# ============================================================
# STEP 1: Generate Ultimate Dataset
# ============================================================
print("\n📥 Generating ultimate dataset...")

def generate_ultimate_dataset(n_samples=500000):
    """Generate 500K samples with maximum variation."""
    np.random.seed(42)
    
    # 70% benign, 30% attacks
    n_benign = int(n_samples * 0.7)
    n_attack = n_samples - n_benign
    
    print(f"   Generating {n_benign:,} benign samples...")
    
    # BENIGN - Multiple traffic patterns
    benign_patterns = []
    
    # Web browsing (40%)
    n_web = int(n_benign * 0.4)
    web = pd.DataFrame({
        'Flow Duration': np.random.exponential(50000, n_web),
        'Total Fwd Packets': np.random.poisson(8, n_web),
        'Total Bwd Packets': np.random.poisson(12, n_web),
        'Fwd Packet Length Total': np.random.exponential(1200, n_web),
        'Bwd Packet Length Total': np.random.exponential(45000, n_web),
        'Fwd Packet Length Max': np.random.exponential(400, n_web),
        'Fwd Packet Length Mean': np.random.exponential(150, n_web),
        'Bwd Packet Length Max': np.random.exponential(1460, n_web),
        'Bwd Packet Length Mean': np.random.exponential(700, n_web),
        'Flow Bytes/s': np.random.exponential(80000, n_web),
        'Flow Packets/s': np.random.exponential(45, n_web),
        'Flow IAT Mean': np.random.exponential(5500, n_web),
        'Flow IAT Std': np.random.exponential(9000, n_web),
        'Fwd IAT Mean': np.random.exponential(6000, n_web),
        'Bwd IAT Mean': np.random.exponential(4000, n_web),
        'FIN Flag Count': np.random.randint(0, 3, n_web),
        'SYN Flag Count': np.random.randint(0, 2, n_web),
        'RST Flag Count': np.random.randint(0, 1, n_web),
        'PSH Flag Count': np.random.randint(0, 6, n_web),
        'ACK Flag Count': np.random.randint(4, 20, n_web),
        'Avg Packet Size': np.random.exponential(280, n_web),
        'Init Win Bytes Fwd': np.random.choice([8192, 16384, 32768, 65535], n_web),
        'Init Win Bytes Bwd': np.random.choice([8192, 16384, 32768, 65535], n_web),
        'Active Mean': np.random.exponential(1500, n_web),
        'Idle Mean': np.random.exponential(6000, n_web),
        'Label': 'BENIGN'
    })
    benign_patterns.append(web)
    
    # Streaming (25%)
    n_stream = int(n_benign * 0.25)
    stream = pd.DataFrame({
        'Flow Duration': np.random.exponential(250000, n_stream),
        'Total Fwd Packets': np.random.poisson(15, n_stream),
        'Total Bwd Packets': np.random.poisson(400, n_stream),
        'Fwd Packet Length Total': np.random.exponential(400, n_stream),
        'Bwd Packet Length Total': np.random.exponential(400000, n_stream),
        'Fwd Packet Length Max': np.random.exponential(80, n_stream),
        'Fwd Packet Length Mean': np.random.exponential(50, n_stream),
        'Bwd Packet Length Max': np.random.exponential(1460, n_stream),
        'Bwd Packet Length Mean': np.random.exponential(1100, n_stream),
        'Flow Bytes/s': np.random.exponential(450000, n_stream),
        'Flow Packets/s': np.random.exponential(180, n_stream),
        'Flow IAT Mean': np.random.exponential(2500, n_stream),
        'Flow IAT Std': np.random.exponential(600, n_stream),
        'Fwd IAT Mean': np.random.exponential(8000, n_stream),
        'Bwd IAT Mean': np.random.exponential(600, n_stream),
        'FIN Flag Count': np.random.randint(0, 2, n_stream),
        'SYN Flag Count': np.random.randint(0, 2, n_stream),
        'RST Flag Count': np.zeros(n_stream, dtype=int),
        'PSH Flag Count': np.random.randint(5, 40, n_stream),
        'ACK Flag Count': np.random.randint(15, 80, n_stream),
        'Avg Packet Size': np.random.exponential(950, n_stream),
        'Init Win Bytes Fwd': np.random.choice([65535], n_stream),
        'Init Win Bytes Bwd': np.random.choice([65535], n_stream),
        'Active Mean': np.random.exponential(40000, n_stream),
        'Idle Mean': np.random.exponential(150, n_stream),
        'Label': 'BENIGN'
    })
    benign_patterns.append(stream)
    
    # Other (35%)
    n_other = n_benign - n_web - n_stream
    other = pd.DataFrame({
        'Flow Duration': np.random.exponential(35000, n_other),
        'Total Fwd Packets': np.random.poisson(5, n_other),
        'Total Bwd Packets': np.random.poisson(5, n_other),
        'Fwd Packet Length Total': np.random.exponential(550, n_other),
        'Bwd Packet Length Total': np.random.exponential(750, n_other),
        'Fwd Packet Length Max': np.random.exponential(180, n_other),
        'Fwd Packet Length Mean': np.random.exponential(90, n_other),
        'Bwd Packet Length Max': np.random.exponential(280, n_other),
        'Bwd Packet Length Mean': np.random.exponential(140, n_other),
        'Flow Bytes/s': np.random.exponential(45000, n_other),
        'Flow Packets/s': np.random.exponential(28, n_other),
        'Flow IAT Mean': np.random.exponential(7500, n_other),
        'Flow IAT Std': np.random.exponential(4500, n_other),
        'Fwd IAT Mean': np.random.exponential(9000, n_other),
        'Bwd IAT Mean': np.random.exponential(8000, n_other),
        'FIN Flag Count': np.random.randint(0, 2, n_other),
        'SYN Flag Count': np.random.randint(0, 2, n_other),
        'RST Flag Count': np.random.randint(0, 1, n_other),
        'PSH Flag Count': np.random.randint(0, 4, n_other),
        'ACK Flag Count': np.random.randint(2, 12, n_other),
        'Avg Packet Size': np.random.exponential(140, n_other),
        'Init Win Bytes Fwd': np.random.choice([8192, 16384, 32768], n_other),
        'Init Win Bytes Bwd': np.random.choice([8192, 16384, 32768], n_other),
        'Active Mean': np.random.exponential(2500, n_other),
        'Idle Mean': np.random.exponential(7000, n_other),
        'Label': 'BENIGN'
    })
    benign_patterns.append(other)
    
    benign = pd.concat(benign_patterns, ignore_index=True)
    
    # ATTACKS - 20 attack types
    print(f"   Generating {n_attack:,} attack samples...")
    
    attack_configs = {
        'DoS Hulk': {'duration': 800, 'fwd_pkts': 60, 'syn': 12, 'bps': 250000},
        'DoS GoldenEye': {'duration': 1500, 'fwd_pkts': 35, 'syn': 6, 'bps': 180000},
        'DoS Slowloris': {'duration': 80000, 'fwd_pkts': 6, 'syn': 2, 'bps': 800},
        'DoS Slowhttptest': {'duration': 45000, 'fwd_pkts': 4, 'syn': 1, 'bps': 400},
        'DDoS': {'duration': 400, 'fwd_pkts': 120, 'syn': 25, 'bps': 600000},
        'DDoS LOIC HTTP': {'duration': 300, 'fwd_pkts': 150, 'syn': 30, 'bps': 800000},
        'DDoS HOIC': {'duration': 200, 'fwd_pkts': 200, 'syn': 40, 'bps': 1000000},
        'PortScan': {'duration': 80, 'fwd_pkts': 2, 'syn': 2, 'bps': 4000},
        'FTP-Patator': {'duration': 2500, 'fwd_pkts': 9, 'syn': 1, 'bps': 2800},
        'SSH-Patator': {'duration': 2200, 'fwd_pkts': 7, 'syn': 1, 'bps': 2200},
        'Bot': {'duration': 28000, 'fwd_pkts': 4, 'syn': 1, 'bps': 450},
        'Botnet ARES': {'duration': 35000, 'fwd_pkts': 5, 'syn': 1, 'bps': 600},
        'Web Attack - Brute Force': {'duration': 4500, 'fwd_pkts': 18, 'syn': 3, 'bps': 4500},
        'Web Attack - XSS': {'duration': 9000, 'fwd_pkts': 22, 'syn': 2, 'bps': 9000},
        'Web Attack - SQL Injection': {'duration': 7500, 'fwd_pkts': 14, 'syn': 2, 'bps': 7500},
        'Web Attack - Command Injection': {'duration': 6000, 'fwd_pkts': 10, 'syn': 2, 'bps': 5000},
        'Infiltration': {'duration': 55000, 'fwd_pkts': 28, 'syn': 3, 'bps': 18000},
        'Heartbleed': {'duration': 800, 'fwd_pkts': 6, 'syn': 1, 'bps': 90000},
        'Backdoor': {'duration': 90000, 'fwd_pkts': 12, 'syn': 2, 'bps': 4500},
        'Ransomware': {'duration': 120000, 'fwd_pkts': 50, 'syn': 5, 'bps': 50000},
    }
    
    attack_dfs = []
    n_per_attack = n_attack // len(attack_configs)
    
    for attack_name, cfg in attack_configs.items():
        n = n_per_attack
        df = pd.DataFrame({
            'Flow Duration': np.random.exponential(cfg['duration'], n),
            'Total Fwd Packets': np.random.poisson(cfg['fwd_pkts'], n),
            'Total Bwd Packets': np.random.poisson(max(1, cfg['fwd_pkts'] // 5), n),
            'Fwd Packet Length Total': np.random.exponential(cfg['fwd_pkts'] * 80, n),
            'Bwd Packet Length Total': np.random.exponential(cfg['fwd_pkts'] * 40, n),
            'Fwd Packet Length Max': np.random.exponential(cfg['fwd_pkts'] * 15, n),
            'Fwd Packet Length Mean': np.random.exponential(cfg['fwd_pkts'] * 8, n),
            'Bwd Packet Length Max': np.random.exponential(180, n),
            'Bwd Packet Length Mean': np.random.exponential(90, n),
            'Flow Bytes/s': np.random.exponential(cfg['bps'], n),
            'Flow Packets/s': np.random.exponential(cfg['fwd_pkts'] * 8, n),
            'Flow IAT Mean': np.random.exponential(cfg['duration'] / 12, n),
            'Flow IAT Std': np.random.exponential(cfg['duration'] / 25, n),
            'Fwd IAT Mean': np.random.exponential(cfg['duration'] / 10, n),
            'Bwd IAT Mean': np.random.exponential(cfg['duration'] / 8, n),
            'FIN Flag Count': np.random.randint(0, 2, n),
            'SYN Flag Count': np.random.poisson(cfg['syn'], n),
            'RST Flag Count': np.random.randint(0, 3, n),
            'PSH Flag Count': np.random.randint(0, max(1, cfg['fwd_pkts'] // 3), n),
            'ACK Flag Count': np.random.randint(0, cfg['fwd_pkts'], n),
            'Avg Packet Size': np.random.exponential(130, n),
            'Init Win Bytes Fwd': np.random.choice([8192, 16384], n),
            'Init Win Bytes Bwd': np.random.choice([8192, 16384], n),
            'Active Mean': np.random.exponential(cfg['duration'] * 0.08, n),
            'Idle Mean': np.random.exponential(800, n),
            'Label': attack_name
        })
        attack_dfs.append(df)
    
    attacks = pd.concat(attack_dfs, ignore_index=True)
    
    # Combine and shuffle
    dataset = pd.concat([benign, attacks], ignore_index=True)
    dataset = dataset.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return dataset

# Generate 500K samples
start = time.time()
df = generate_ultimate_dataset(500000)
gen_time = time.time() - start
print(f"   ✅ Generated {len(df):,} samples in {gen_time:.1f}s")

# Save
csv_path = os.path.join(DATA_DIR, "ultimate_dataset.csv")
df.to_csv(csv_path, index=False)
print(f"   💾 Saved to {csv_path}")

# ============================================================
# STEP 2: Prepare & Train
# ============================================================
print("\n📊 Preparing data...")

df['is_attack'] = (df['Label'] != 'BENIGN').astype(int)
feature_cols = [c for c in df.columns if c not in ['Label', 'is_attack']]

# Clean
numeric_cols = df[feature_cols].select_dtypes(include=[np.number]).columns
df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())

X = df[feature_cols].values
y = df['is_attack'].values

print(f"   Features: {len(feature_cols)}")
print(f"   Samples: {len(X):,}")
print(f"   Attack ratio: {y.mean():.2%}")

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Scale
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(f"   Training: {len(X_train):,} | Test: {len(X_test):,}")

# Train Random Forest (proven best)
print("\n🏋️ Training Random Forest on 500K samples...")
start = time.time()

rf = RandomForestClassifier(
    n_estimators=200,  # More trees
    max_depth=30,      # Deeper trees
    min_samples_split=5,
    n_jobs=-1,
    random_state=42
)

rf.fit(X_train_scaled, y_train)
train_time = time.time() - start
print(f"   ✅ Trained in {train_time:.1f}s")

# Evaluate
y_pred = rf.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n🏆 Accuracy: {accuracy:.4%}")
print("\n📈 Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Benign', 'Attack']))

# Save
print("\n💾 Saving model...")

model_data = {
    'model': rf,
    'scaler': scaler,
    'features': feature_cols,
    'accuracy': accuracy,
    'model_type': 'RandomForest',
    'training_samples': len(X_train),
    'attack_types': df['Label'].nunique()
}

with open("trained_model.pkl", 'wb') as f:
    pickle.dump(model_data, f)

with open("trained_model_ultimate.pkl", 'wb') as f:
    pickle.dump(model_data, f)

print("   ✅ Model saved!")

# Summary
print("\n" + "=" * 70)
print("📊 ULTIMATE TRAINING SUMMARY")
print("=" * 70)
print(f"""
Dataset:
  - Total samples: {len(df):,}
  - Features: {len(feature_cols)}
  - Attack types: {df['Label'].nunique()}
  - Attack ratio: {y.mean():.2%}

Model:
  - Algorithm: Random Forest
  - Trees: 200
  - Max Depth: 30
  - Training time: {train_time:.1f}s
  - Accuracy: {accuracy:.4%}

Attack Types ({df['Label'].nunique()} total):
""")

for label in sorted(df['Label'].unique()):
    if label != 'BENIGN':
        count = (df['Label'] == label).sum()
        print(f"  - {label}: {count:,}")

print(f"""
Files:
  - trained_model.pkl (production)
  - trained_model_ultimate.pkl (backup)
  - datasets/ultimate_dataset.csv

✅ ULTIMATE training complete!
""")
