import pandas as pd

def get_basic_stats(df):
    """Returns descriptive statistics for packet lengths."""
    return df['length'].describe()

def get_top_talkers(df, n=5):
    """Returns top N source IPs by packet count."""
    return df['src_ip'].value_counts().head(n)

def get_protocol_stats(df):
    """Returns packet counts and average length per protocol."""
    return df.groupby('protocol', observed=False).agg({
        'length': ['count', 'mean', 'max'],
        'id': 'count'
    })

def create_pivot_table(df):
    """Creates a pivot table of avg length by IP and protocol."""
    return df.pivot_table(
        values='length',
        index='src_ip',
        columns='protocol',
        aggfunc='mean',
        fill_value=0,
        observed=False
    )

def detect_zscore_anomalies(df, threshold=3):
    """
    Detects anomalies using Z-Score (Standard Deviations from Mean).
    Returns rows where packet size is > threshold * std_dev away from mean.
    """
    # 1. Calculate Mean and Std Dev
    mu = df['length'].mean()
    sigma = df['length'].std()
    
    # 2. Calculate Z-Score: (Value - Mean) / StdDev
    df = df.copy() # Avoid SettingWithCopy warning
    df['z_score'] = (df['length'] - mu) / sigma
    
    # 3. Filter for Outliers (|Z| > threshold)
    anomalies = df[abs(df['z_score']) > threshold]
    
    return anomalies[['timestamp', 'src_ip', 'length', 'z_score']]
