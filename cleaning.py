import pandas as pd

def clean_timestamps(df):
    """Converts timestamp column to datetime objects."""
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

def parse_ips(df):
    """Adds IP address metadata (first octet, local check)."""
    if 'src_ip' in df.columns:
        # Split IP by dots, get first octet
        df['first_octet'] = df['src_ip'].str.split('.').str[0]
        # Check if IP starts with "192" (local network)
        df['is_local'] = df['src_ip'].str.startswith('192')
    return df

def optimize_memory(df):
    """Converts object columns to categories to save memory."""
    for col in ['protocol', 'src_ip', 'dst_ip']:
        if col in df.columns and df[col].dtype == 'object':
             df[col] = df[col].astype('category')
    return df
