import sqlite3
import pandas as pd

def load_traffic_data(db_path):
    """
    Connects to the SQLite database and loads traffic data into a Pandas DataFrame.
    """
    try:
        # Timeout of 5 seconds to prevent hanging if DB is locked
        conn = sqlite3.connect(db_path, timeout=5)
        # Optimize: Only load last 2000 packets to prevent freezing
        df = pd.read_sql("SELECT * FROM traffic ORDER BY timestamp DESC LIMIT 2000", conn)
        df = df.sort_values('timestamp') # Sort back to chronological order
        conn.close()
        return df
    except Exception as e:
        print(f"Error loading data: {e}")
        return pd.DataFrame() # Return empty DataFrame on error
