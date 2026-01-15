import pandas as pd

def add_time_series_features(df):
    """Adds rolling windows and expanding sum features."""
    # Ensure sorted by time
    df = df.sort_values('timestamp')
    
    # 1. Rolling Average (window = 5 packets)
    df['rolling_avg_len'] = df['length'].rolling(window=5).mean()
    
    # 2. Expanding Sum (Running Total)
    df['running_total_bytes'] = df['length'].expanding().sum()
    
    # 3. Lag features (Previous packet length)
    df['prev_length'] = df['length'].shift(1)

    # 4. Protocol One-Hot Encoding (Fixed!)
    # Create dummies but keep original
    dummies = pd.get_dummies(df['protocol'], prefix='proto', dtype=int)
    df = pd.concat([df, dummies], axis=1)

    # 5. Time Difference (New!)
    # Calculate seconds since previous packet
    df['time_diff'] = df['timestamp'].diff().dt.total_seconds().fillna(0.0)
    
    # 6. Byte Rate (Bytes per Second)
    # Avoid division by zero!
    df['byte_rate'] = df['length'] / (df['time_diff'] + 0.001)
    return df

def resample_traffic(df, rule='1s'):
    """Resamples traffic count by time rule (e.g., '1s', '1min')."""
    if 'timestamp' not in df.columns:
        return pd.Series()
        
    df_time = df.set_index('timestamp')
    return df_time.resample(rule).size()

def prepare_for_ml(df, target_col=None, split_ratio=0.5):
    """
    Prepares Data for ML:
    1. Drops non-numeric columns (or encodes them)
    2. Handles missing values (drops rows with NaNs usually created by lag features)
    3. Splits into Train/Test sets
    """
    # 1. Drop NaNs created by rolling/lag
    df_clean = df.dropna().copy()
    
    # 2. Select numerical features
    # (In a real app, we'd OneHotEncode protocol, but for now let's just use numeric)
    numeric_cols = df_clean.select_dtypes(include=['number']).columns
    features = df_clean[numeric_cols]
    
    # 3. Split Data (Time-based split is better for network traffic!)
    split_idx = int(len(features) * split_ratio)
    train_df = features.iloc[:split_idx]
    test_df = features.iloc[split_idx:]
    
    return train_df, test_df
