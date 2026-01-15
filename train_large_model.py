"""
train_large_model.py - Train on Large CICIDS2017-style Dataset
Full feature training with multiple models and comprehensive evaluation.
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pickle
import os
import time

print("=" * 60)
print("🧠 NetGuardAI - Large Dataset Training")
print("=" * 60)

# ============================================================
# STEP 1: Load Dataset
# ============================================================
print("\n📥 Loading dataset...")

DATA_DIR = "datasets"
CSV_FILE = os.path.join(DATA_DIR, "cicids2017_sample.csv")

# Check if dataset exists, if not create it
if not os.path.exists(CSV_FILE):
    print("   Dataset not found. Running download_cicids.py first...")
    exec(open("download_cicids.py").read())

df = pd.read_csv(CSV_FILE)
print(f"   ✅ Loaded {len(df)} samples")
print(f"   📊 Features: {len(df.columns) - 1}")  # -1 for label column

# ============================================================
# STEP 2: Data Cleaning (Handling Uncleaned Data)
# ============================================================
print("\n🧹 Cleaning data...")

# Check for missing values
missing = df.isnull().sum().sum()
print(f"   Missing values: {missing}")

# Fill missing with median (robust to outliers)
numeric_cols = df.select_dtypes(include=[np.number]).columns
df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())

# Handle infinite values
df = df.replace([np.inf, -np.inf], np.nan)
df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())

# Check for negative values in flow features (shouldn't exist)
for col in numeric_cols:
    if (df[col] < 0).any():
        df[col] = df[col].abs()  # Take absolute value

print(f"   ✅ Data cleaned")

# ============================================================
# STEP 3: Feature Engineering
# ============================================================
print("\n🔧 Engineering features...")

# Create binary label (0 = BENIGN, 1 = ATTACK)
df['is_attack'] = (df['Label'] != 'BENIGN').astype(int)

# Create ratio features
df['fwd_bwd_ratio'] = df['Total Fwd Packets'] / (df['Total Backward Packets'] + 1)
df['bytes_per_packet'] = (df['Total Length of Fwd Packets'] + df['Total Length of Bwd Packets']) / (df['Total Fwd Packets'] + df['Total Backward Packets'] + 1)

# Log transform skewed features
skewed_features = ['Flow Duration', 'Flow Bytes/s', 'Flow Packets/s']
for col in skewed_features:
    df[f'{col}_log'] = np.log1p(df[col])

print(f"   ✅ Created {3 + len(skewed_features)} new features")

# ============================================================
# STEP 4: Prepare Training Data
# ============================================================
print("\n📊 Preparing training data...")

# Feature columns (all numeric except labels)
feature_cols = [col for col in df.columns if col not in ['Label', 'is_attack']]

X = df[feature_cols].values
y = df['is_attack'].values

print(f"   Features: {len(feature_cols)}")
print(f"   Samples: {len(X)}")
print(f"   Attack ratio: {y.mean():.2%}")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, 
    test_size=0.2, 
    random_state=42,
    stratify=y
)

print(f"   Training set: {len(X_train)}")
print(f"   Test set: {len(X_test)}")

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ============================================================
# STEP 5: Train Isolation Forest (Unsupervised)
# ============================================================
print("\n🏋️ Training Isolation Forest...")
start_time = time.time()

# Calculate contamination from actual attack ratio
contamination = y_train.mean()

iso_forest = IsolationForest(
    n_estimators=150,           # More trees for better accuracy
    contamination=contamination,
    max_samples='auto',
    random_state=42,
    n_jobs=-1,
    verbose=0
)

iso_forest.fit(X_train_scaled)
iso_time = time.time() - start_time
print(f"   ✅ Trained in {iso_time:.2f}s")

# Predict
y_pred_iso = iso_forest.predict(X_test_scaled)
y_pred_iso_binary = np.where(y_pred_iso == -1, 1, 0)

# ============================================================
# STEP 6: Train Random Forest (Supervised)
# ============================================================
print("\n🏋️ Training Random Forest (Supervised)...")
start_time = time.time()

rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    verbose=0
)

rf.fit(X_train_scaled, y_train)
rf_time = time.time() - start_time
print(f"   ✅ Trained in {rf_time:.2f}s")

# Predict
y_pred_rf = rf.predict(X_test_scaled)

# ============================================================
# STEP 7: Evaluate Models
# ============================================================
print("\n" + "=" * 60)
print("📈 MODEL EVALUATION")
print("=" * 60)

# Isolation Forest Results
print("\n--- Isolation Forest (Unsupervised) ---")
iso_acc = accuracy_score(y_test, y_pred_iso_binary)
print(f"Accuracy: {iso_acc:.2%}")
print(classification_report(y_test, y_pred_iso_binary, target_names=['Benign', 'Attack']))

# Random Forest Results
print("\n--- Random Forest (Supervised) ---")
rf_acc = accuracy_score(y_test, y_pred_rf)
print(f"Accuracy: {rf_acc:.2%}")
print(classification_report(y_test, y_pred_rf, target_names=['Benign', 'Attack']))

# Feature Importance (from Random Forest)
print("\n📊 Top 10 Most Important Features:")
importance = pd.DataFrame({
    'feature': feature_cols,
    'importance': rf.feature_importances_
}).sort_values('importance', ascending=False)
print(importance.head(10).to_string(index=False))

# ============================================================
# STEP 8: Save Best Model
# ============================================================
print("\n💾 Saving models...")

# Save both models
model_data = {
    'isolation_forest': iso_forest,
    'random_forest': rf,
    'scaler': scaler,
    'features': feature_cols,
    'iso_accuracy': iso_acc,
    'rf_accuracy': rf_acc,
    'training_samples': len(X_train)
}

MODEL_FILE = "trained_model_large.pkl"
with open(MODEL_FILE, 'wb') as f:
    pickle.dump(model_data, f)

print(f"   ✅ Models saved to: {MODEL_FILE}")

# Also update the main model file with the better model
if rf_acc > iso_acc:
    best_model = {
        'model': rf,
        'scaler': scaler,
        'features': feature_cols,
        'accuracy': rf_acc,
        'model_type': 'RandomForest'
    }
else:
    best_model = {
        'model': iso_forest,
        'scaler': scaler,
        'features': feature_cols,
        'accuracy': iso_acc,
        'model_type': 'IsolationForest'
    }

with open("trained_model.pkl", 'wb') as f:
    pickle.dump(best_model, f)

print(f"   ✅ Best model saved to: trained_model.pkl")

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 60)
print("📊 TRAINING SUMMARY")
print("=" * 60)
print(f"""
Dataset:
  - Total samples: {len(df)}
  - Features: {len(feature_cols)}
  - Attack types: {df['Label'].nunique()}
  - Attack ratio: {y.mean():.2%}

Models:
  1. Isolation Forest (Unsupervised)
     - Accuracy: {iso_acc:.2%}
     - Training time: {iso_time:.2f}s
     
  2. Random Forest (Supervised)
     - Accuracy: {rf_acc:.2%}
     - Training time: {rf_time:.2f}s

Best Model: {'Random Forest' if rf_acc > iso_acc else 'Isolation Forest'}
Best Accuracy: {max(rf_acc, iso_acc):.2%}

Files Saved:
  - trained_model_large.pkl (both models)
  - trained_model.pkl (best model for dashboard)
""")

print("✅ Training complete! Run 'streamlit run dashboard.py' to test.")
