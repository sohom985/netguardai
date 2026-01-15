"""
train_massive.py - Train on Massive Dataset
Generates 200,000+ samples with extensive attack variations.
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os
import time
import warnings
warnings.filterwarnings('ignore')

print("=" * 70)
print("🧠 NetGuardAI - MASSIVE Dataset Training (200,000+ samples)")
print("=" * 70)

DATA_DIR = "datasets"
os.makedirs(DATA_DIR, exist_ok=True)

# ============================================================
# STEP 1: Generate Massive Dataset
# ============================================================
print("\n📥 Generating massive dataset...")

def generate_massive_dataset(n_samples=200000):
    """Generate 200K samples with 15 attack types and advanced features."""
    np.random.seed(42)
    
    # 70% benign, 30% attacks (realistic)
    n_benign = int(n_samples * 0.7)
    n_attack = n_samples - n_benign
    
    print(f"   Generating {n_benign:,} benign samples...")
    
    # BENIGN TRAFFIC (Various normal patterns)
    benign_types = {
        'Web Browsing': 0.4,
        'Email': 0.15,
        'File Transfer': 0.15,
        'Streaming': 0.15,
        'VoIP': 0.1,
        'DNS': 0.05
    }
    
    benign_dfs = []
    for traffic_type, ratio in benign_types.items():
        n = int(n_benign * ratio)
        
        if traffic_type == 'Web Browsing':
            df = pd.DataFrame({
                'Flow Duration': np.random.exponential(50000, n),
                'Total Fwd Packets': np.random.poisson(10, n),
                'Total Bwd Packets': np.random.poisson(15, n),
                'Fwd Packet Length Total': np.random.exponential(1500, n),
                'Bwd Packet Length Total': np.random.exponential(50000, n),
                'Fwd Packet Length Max': np.random.exponential(500, n),
                'Fwd Packet Length Min': np.random.exponential(40, n),
                'Fwd Packet Length Mean': np.random.exponential(150, n),
                'Bwd Packet Length Max': np.random.exponential(1460, n),
                'Bwd Packet Length Mean': np.random.exponential(800, n),
                'Flow Bytes/s': np.random.exponential(100000, n),
                'Flow Packets/s': np.random.exponential(50, n),
                'Flow IAT Mean': np.random.exponential(5000, n),
                'Flow IAT Std': np.random.exponential(10000, n),
                'Fwd IAT Total': np.random.exponential(30000, n),
                'Bwd IAT Total': np.random.exponential(40000, n),
                'FIN Flag Count': np.random.randint(0, 3, n),
                'SYN Flag Count': np.random.randint(0, 2, n),
                'RST Flag Count': np.random.randint(0, 1, n),
                'PSH Flag Count': np.random.randint(0, 5, n),
                'ACK Flag Count': np.random.randint(5, 20, n),
                'URG Flag Count': np.zeros(n),
                'Avg Packet Size': np.random.exponential(300, n),
                'Subflow Fwd Packets': np.random.poisson(5, n),
                'Subflow Bwd Packets': np.random.poisson(8, n),
                'Init Win Bytes Fwd': np.random.choice([8192, 16384, 32768, 65535], n),
                'Init Win Bytes Bwd': np.random.choice([8192, 16384, 32768, 65535], n),
                'Active Mean': np.random.exponential(1000, n),
                'Idle Mean': np.random.exponential(5000, n),
                'Label': 'BENIGN'
            })
        elif traffic_type == 'Streaming':
            df = pd.DataFrame({
                'Flow Duration': np.random.exponential(300000, n),  # Longer
                'Total Fwd Packets': np.random.poisson(20, n),
                'Total Bwd Packets': np.random.poisson(500, n),  # Mostly download
                'Fwd Packet Length Total': np.random.exponential(500, n),
                'Bwd Packet Length Total': np.random.exponential(500000, n),  # Large
                'Fwd Packet Length Max': np.random.exponential(100, n),
                'Fwd Packet Length Min': np.random.exponential(40, n),
                'Fwd Packet Length Mean': np.random.exponential(60, n),
                'Bwd Packet Length Max': np.random.exponential(1460, n),
                'Bwd Packet Length Mean': np.random.exponential(1200, n),
                'Flow Bytes/s': np.random.exponential(500000, n),  # High bandwidth
                'Flow Packets/s': np.random.exponential(200, n),
                'Flow IAT Mean': np.random.exponential(2000, n),
                'Flow IAT Std': np.random.exponential(500, n),  # Low variance
                'Fwd IAT Total': np.random.exponential(10000, n),
                'Bwd IAT Total': np.random.exponential(200000, n),
                'FIN Flag Count': np.random.randint(0, 2, n),
                'SYN Flag Count': np.random.randint(0, 2, n),
                'RST Flag Count': np.zeros(n, dtype=int),
                'PSH Flag Count': np.random.randint(5, 50, n),
                'ACK Flag Count': np.random.randint(20, 100, n),
                'URG Flag Count': np.zeros(n),
                'Avg Packet Size': np.random.exponential(1000, n),
                'Subflow Fwd Packets': np.random.poisson(10, n),
                'Subflow Bwd Packets': np.random.poisson(250, n),
                'Init Win Bytes Fwd': np.random.choice([65535], n),
                'Init Win Bytes Bwd': np.random.choice([65535], n),
                'Active Mean': np.random.exponential(50000, n),
                'Idle Mean': np.random.exponential(100, n),
                'Label': 'BENIGN'
            })
        else:  # Generic other traffic
            df = pd.DataFrame({
                'Flow Duration': np.random.exponential(30000, n),
                'Total Fwd Packets': np.random.poisson(5, n),
                'Total Bwd Packets': np.random.poisson(5, n),
                'Fwd Packet Length Total': np.random.exponential(500, n),
                'Bwd Packet Length Total': np.random.exponential(800, n),
                'Fwd Packet Length Max': np.random.exponential(200, n),
                'Fwd Packet Length Min': np.random.exponential(40, n),
                'Fwd Packet Length Mean': np.random.exponential(100, n),
                'Bwd Packet Length Max': np.random.exponential(300, n),
                'Bwd Packet Length Mean': np.random.exponential(150, n),
                'Flow Bytes/s': np.random.exponential(50000, n),
                'Flow Packets/s': np.random.exponential(30, n),
                'Flow IAT Mean': np.random.exponential(8000, n),
                'Flow IAT Std': np.random.exponential(5000, n),
                'Fwd IAT Total': np.random.exponential(20000, n),
                'Bwd IAT Total': np.random.exponential(20000, n),
                'FIN Flag Count': np.random.randint(0, 2, n),
                'SYN Flag Count': np.random.randint(0, 2, n),
                'RST Flag Count': np.random.randint(0, 1, n),
                'PSH Flag Count': np.random.randint(0, 3, n),
                'ACK Flag Count': np.random.randint(2, 10, n),
                'URG Flag Count': np.zeros(n),
                'Avg Packet Size': np.random.exponential(150, n),
                'Subflow Fwd Packets': np.random.poisson(3, n),
                'Subflow Bwd Packets': np.random.poisson(3, n),
                'Init Win Bytes Fwd': np.random.choice([8192, 16384, 32768], n),
                'Init Win Bytes Bwd': np.random.choice([8192, 16384, 32768], n),
                'Active Mean': np.random.exponential(2000, n),
                'Idle Mean': np.random.exponential(8000, n),
                'Label': 'BENIGN'
            })
        benign_dfs.append(df)
    
    benign = pd.concat(benign_dfs, ignore_index=True)
    
    # ATTACK TRAFFIC (15 different attack types)
    print(f"   Generating {n_attack:,} attack samples...")
    
    attack_configs = {
        'DoS Hulk': {'duration': 1000, 'fwd_packets': 50, 'syn_count': 10, 'bytes_per_s': 200000},
        'DoS GoldenEye': {'duration': 2000, 'fwd_packets': 30, 'syn_count': 5, 'bytes_per_s': 150000},
        'DoS Slowloris': {'duration': 100000, 'fwd_packets': 5, 'syn_count': 2, 'bytes_per_s': 1000},
        'DoS Slowhttptest': {'duration': 50000, 'fwd_packets': 3, 'syn_count': 1, 'bytes_per_s': 500},
        'DDoS': {'duration': 500, 'fwd_packets': 100, 'syn_count': 20, 'bytes_per_s': 500000},
        'PortScan': {'duration': 100, 'fwd_packets': 2, 'syn_count': 2, 'bytes_per_s': 5000},
        'FTP-Patator': {'duration': 3000, 'fwd_packets': 8, 'syn_count': 1, 'bytes_per_s': 3000},
        'SSH-Patator': {'duration': 2500, 'fwd_packets': 6, 'syn_count': 1, 'bytes_per_s': 2500},
        'Bot': {'duration': 30000, 'fwd_packets': 3, 'syn_count': 1, 'bytes_per_s': 500},
        'Web Attack - Brute Force': {'duration': 5000, 'fwd_packets': 15, 'syn_count': 3, 'bytes_per_s': 5000},
        'Web Attack - XSS': {'duration': 10000, 'fwd_packets': 20, 'syn_count': 2, 'bytes_per_s': 10000},
        'Web Attack - SQL Injection': {'duration': 8000, 'fwd_packets': 12, 'syn_count': 2, 'bytes_per_s': 8000},
        'Infiltration': {'duration': 60000, 'fwd_packets': 25, 'syn_count': 3, 'bytes_per_s': 20000},
        'Heartbleed': {'duration': 1000, 'fwd_packets': 5, 'syn_count': 1, 'bytes_per_s': 100000},
        'Backdoor': {'duration': 100000, 'fwd_packets': 10, 'syn_count': 2, 'bytes_per_s': 5000},
    }
    
    attack_dfs = []
    n_per_attack = n_attack // len(attack_configs)
    
    for attack_name, config in attack_configs.items():
        n = n_per_attack
        df = pd.DataFrame({
            'Flow Duration': np.random.exponential(config['duration'], n),
            'Total Fwd Packets': np.random.poisson(config['fwd_packets'], n),
            'Total Bwd Packets': np.random.poisson(max(1, config['fwd_packets'] // 5), n),
            'Fwd Packet Length Total': np.random.exponential(config['fwd_packets'] * 100, n),
            'Bwd Packet Length Total': np.random.exponential(config['fwd_packets'] * 50, n),
            'Fwd Packet Length Max': np.random.exponential(config['fwd_packets'] * 20, n),
            'Fwd Packet Length Min': np.random.exponential(40, n),
            'Fwd Packet Length Mean': np.random.exponential(config['fwd_packets'] * 10, n),
            'Bwd Packet Length Max': np.random.exponential(200, n),
            'Bwd Packet Length Mean': np.random.exponential(100, n),
            'Flow Bytes/s': np.random.exponential(config['bytes_per_s'], n),
            'Flow Packets/s': np.random.exponential(config['fwd_packets'] * 10, n),
            'Flow IAT Mean': np.random.exponential(config['duration'] / 10, n),
            'Flow IAT Std': np.random.exponential(config['duration'] / 20, n),
            'Fwd IAT Total': np.random.exponential(config['duration'] * 0.8, n),
            'Bwd IAT Total': np.random.exponential(config['duration'] * 0.5, n),
            'FIN Flag Count': np.random.randint(0, 2, n),
            'SYN Flag Count': np.random.poisson(config['syn_count'], n),
            'RST Flag Count': np.random.randint(0, 3, n),
            'PSH Flag Count': np.random.randint(0, config['fwd_packets'] // 2, n),
            'ACK Flag Count': np.random.randint(0, config['fwd_packets'], n),
            'URG Flag Count': np.random.randint(0, 2, n),
            'Avg Packet Size': np.random.exponential(150, n),
            'Subflow Fwd Packets': np.random.poisson(config['fwd_packets'] // 2, n),
            'Subflow Bwd Packets': np.random.poisson(2, n),
            'Init Win Bytes Fwd': np.random.choice([8192, 16384], n),
            'Init Win Bytes Bwd': np.random.choice([8192, 16384], n),
            'Active Mean': np.random.exponential(config['duration'] * 0.1, n),
            'Idle Mean': np.random.exponential(1000, n),
            'Label': attack_name
        })
        attack_dfs.append(df)
    
    attacks = pd.concat(attack_dfs, ignore_index=True)
    
    # Combine and shuffle
    dataset = pd.concat([benign, attacks], ignore_index=True)
    dataset = dataset.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return dataset

# Generate dataset
start = time.time()
df = generate_massive_dataset(200000)
gen_time = time.time() - start
print(f"   ✅ Generated {len(df):,} samples in {gen_time:.1f}s")

# Save dataset
csv_path = os.path.join(DATA_DIR, "massive_dataset.csv")
df.to_csv(csv_path, index=False)
print(f"   💾 Saved to {csv_path}")

# ============================================================
# STEP 2: Data Preparation
# ============================================================
print("\n📊 Preparing data...")

# Binary label
df['is_attack'] = (df['Label'] != 'BENIGN').astype(int)

# Features
feature_cols = [c for c in df.columns if c not in ['Label', 'is_attack']]

# Handle infinities and NaN only on numeric columns
numeric_cols = df[feature_cols].select_dtypes(include=[np.number]).columns
df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())

X = df[feature_cols].values
y = df['is_attack'].values

print(f"   Features: {len(feature_cols)}")
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

# ============================================================
# STEP 3: Train Multiple Models
# ============================================================
print("\n🏋️ Training models...")

results = {}

# 1. Random Forest
print("   [1/3] Random Forest...")
start = time.time()
rf = RandomForestClassifier(n_estimators=150, max_depth=25, n_jobs=-1, random_state=42)
rf.fit(X_train_scaled, y_train)
y_pred = rf.predict(X_test_scaled)
rf_acc = accuracy_score(y_test, y_pred)
rf_time = time.time() - start
results['Random Forest'] = {'model': rf, 'accuracy': rf_acc, 'time': rf_time}
print(f"         Accuracy: {rf_acc:.2%} ({rf_time:.1f}s)")

# 2. Gradient Boosting
print("   [2/3] Gradient Boosting...")
start = time.time()
gb = GradientBoostingClassifier(n_estimators=100, max_depth=10, random_state=42)
gb.fit(X_train_scaled, y_train)
y_pred = gb.predict(X_test_scaled)
gb_acc = accuracy_score(y_test, y_pred)
gb_time = time.time() - start
results['Gradient Boosting'] = {'model': gb, 'accuracy': gb_acc, 'time': gb_time}
print(f"         Accuracy: {gb_acc:.2%} ({gb_time:.1f}s)")

# 3. Neural Network
print("   [3/3] Neural Network (MLP)...")
start = time.time()
mlp = MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=200, random_state=42)
mlp.fit(X_train_scaled, y_train)
y_pred = mlp.predict(X_test_scaled)
mlp_acc = accuracy_score(y_test, y_pred)
mlp_time = time.time() - start
results['Neural Network'] = {'model': mlp, 'accuracy': mlp_acc, 'time': mlp_time}
print(f"         Accuracy: {mlp_acc:.2%} ({mlp_time:.1f}s)")

# ============================================================
# STEP 4: Select Best Model
# ============================================================
best_name = max(results, key=lambda x: results[x]['accuracy'])
best_model = results[best_name]['model']
best_acc = results[best_name]['accuracy']

print(f"\n🏆 Best Model: {best_name} ({best_acc:.2%})")

# Detailed report for best model
y_pred_best = best_model.predict(X_test_scaled)
print("\n📈 Classification Report:")
print(classification_report(y_test, y_pred_best, target_names=['Benign', 'Attack']))

# ============================================================
# STEP 5: Save Models
# ============================================================
print("\n💾 Saving models...")

# Save all models
all_models = {
    'random_forest': results['Random Forest']['model'],
    'gradient_boosting': results['Gradient Boosting']['model'],
    'neural_network': results['Neural Network']['model'],
    'scaler': scaler,
    'features': feature_cols,
    'accuracies': {k: v['accuracy'] for k, v in results.items()},
    'best_model': best_name,
    'training_samples': len(X_train)
}

with open("trained_model_massive.pkl", 'wb') as f:
    pickle.dump(all_models, f)

# Update main model file with best
best_data = {
    'model': best_model,
    'scaler': scaler,
    'features': feature_cols,
    'accuracy': best_acc,
    'model_type': best_name
}

with open("trained_model.pkl", 'wb') as f:
    pickle.dump(best_data, f)

print("   ✅ All models saved!")

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 70)
print("📊 MASSIVE TRAINING SUMMARY")
print("=" * 70)

print(f"""
Dataset:
  - Total samples: {len(df):,}
  - Features: {len(feature_cols)}
  - Attack types: {df['Label'].nunique()}
  - Attack ratio: {y.mean():.2%}

Models Trained:
""")

for name, data in sorted(results.items(), key=lambda x: -x[1]['accuracy']):
    star = "⭐" if name == best_name else "  "
    print(f"  {star} {name}: {data['accuracy']:.2%} ({data['time']:.1f}s)")

print(f"""
Best Model: {best_name}
Best Accuracy: {best_acc:.2%}

Files Saved:
  - trained_model_massive.pkl (all 3 models)
  - trained_model.pkl (best model - {best_name})
  - datasets/massive_dataset.csv

Attack Types Covered:
""")

for label in df['Label'].unique():
    if label != 'BENIGN':
        count = (df['Label'] == label).sum()
        print(f"  - {label}: {count:,}")

print("\n" + "=" * 70)
print("✅ Training complete! Ready for production.")
print("=" * 70)
