"""
ml_detector.py - Machine Learning Anomaly Detection
Uses pre-trained Isolation Forest model to detect unusual network traffic.
"""
from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np
import pickle
import os

# Path to trained model
MODEL_FILE = "trained_model.pkl"

# The ML Model and Scaler
model = None
scaler = None

def load_trained_model():
    """Load the pre-trained model from file."""
    global model, scaler
    
    if os.path.exists(MODEL_FILE):
        try:
            with open(MODEL_FILE, 'rb') as f:
                model_data = pickle.load(f)
            model = model_data['model']
            scaler = model_data['scaler']
            print(f"✅ Loaded trained model (accuracy: {model_data['accuracy']:.2%})")
            return True
        except Exception as e:
            print(f"⚠️ Could not load model: {e}")
            return False
    return False

def train_model(df):
    """
    Trains the Isolation Forest on historical traffic data.
    Called automatically if no pre-trained model exists.
    """
    global model, scaler
    
    # Try to load pre-trained model first
    if load_trained_model():
        return True
    
    if df.empty or len(df) < 100:
        print("Not enough data to train (need 100+ rows)")
        return False
    
    from sklearn.preprocessing import StandardScaler
    
    features = ['length']
    X = df[features].copy().fillna(0)
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Create and train the model
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_scaled)
    print(f"✅ Model trained on {len(X)} samples")
    return True

def predict(df):
    """
    Predicts anomalies in new data.
    Returns: DataFrame with 'ml_prediction' column
    """
    global model, scaler
    
    # Try to load pre-trained model if not loaded
    if model is None:
        if not load_trained_model():
            train_model(df)
    
    if model is None:
        df = df.copy()
        df['ml_prediction'] = 'Unknown'
        df['anomaly_score'] = 0
        return df
    
    features = ['length']
    X = df[features].copy().fillna(0)
    
    # Scale if scaler exists
    if scaler is not None:
        X_scaled = scaler.transform(X)
    else:
        X_scaled = X.values
    
    # Get predictions (-1 = anomaly, 1 = normal)
    predictions = model.predict(X_scaled)
    
    # Get anomaly scores (lower = more anomalous)
    scores = model.decision_function(X_scaled)
    
    df = df.copy()
    df['ml_prediction'] = np.where(predictions == -1, '🔴 Anomaly', '🟢 Normal')
    df['anomaly_score'] = scores
    
    return df

# Test the module
if __name__ == "__main__":
    print("🧠 ML Detector Test")
    print("=" * 40)
    
    # Try to load trained model
    if load_trained_model():
        print("Using pre-trained model!")
    else:
        print("No pre-trained model found, run train_model.py first!")
    
    # Test with sample data
    test_data = pd.DataFrame({
        'length': [66, 100, 150, 5000, 40000, 120]  # Mix of normal and anomalous
    })
    
    result = predict(test_data)
    print("\nPredictions:")
    print(result[['length', 'ml_prediction', 'anomaly_score']])