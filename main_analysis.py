from data_loader import load_traffic_data
from cleaning import clean_timestamps, parse_ips, optimize_memory
from analysis import get_basic_stats, get_top_talkers, get_protocol_stats, create_pivot_table, detect_zscore_anomalies
from enrichment import merge_threat_intel
from features import add_time_series_features, resample_traffic, prepare_for_ml
from visualizer import plot_traffic_over_time, plot_protocol_distribution, plot_packet_size_hist

DB_FILE = "netguard.db"

def main():
    print("🚀 Starting NetGuardAI Traffic Analysis...\n")

    # 1. Load
    print(f"--- Loading Data from {DB_FILE} ---")
    df = load_traffic_data(DB_FILE)
    if df.empty:
        print("No data found! Run sniffer.py first.")
        return

    # 2. Clean & Optimize
    print("--- Cleaning & Optimizing Data ---")
    df = clean_timestamps(df)
    df = parse_ips(df)
    df = optimize_memory(df)
    print(f"Loaded {len(df)} packets.\n")

    # 3. Enrich (Threat Intel)
    print("--- Enriching with Threat Intelligence (Destination IPs) ---")
    df_enriched = merge_threat_intel(df)
    print(df_enriched[['dst_ip', 'country', 'city', 'isp', 'threat_level']].head(10), "\n")

    # 4. Feature Engineering (New Phase 6 Stuff!)
    print("--- Generating Time Series Features ---")
    df = add_time_series_features(df)
    print(df[['timestamp', 'rolling_avg_len', 'running_total_bytes', 'prev_length']].tail(), "\n")
    
    print("--- Preparing Data for ML (Train/Test Split) ---")
    train_df, test_df = prepare_for_ml(df)
    print(f"Train Shape: {train_df.shape}")
    print(f"Test Shape:  {test_df.shape}")
    print("Training Features:", list(train_df.columns), "\n")

    # 5. Analysis
    print("--- Basic Stats ---")
    print(get_basic_stats(df), "\n")

    print("--- Top Talkers ---")
    print(get_top_talkers(df), "\n")

    print("--- Protocol Stats ---")
    print(get_protocol_stats(df), "\n")

    print("--- Pivot Table (Avg Length by IP & Protocol) ---")
    print(create_pivot_table(df), "\n")

    # 6. Time Series Analysis
    print("--- Traffic Volume per Second ---")
    print(resample_traffic(df, '1s').head())
    
    # 7. Scientific Statistics (Phase 9)
    print("\n--- Anomaly Detection (Z-Score) ---")
    anomalies = detect_zscore_anomalies(df, threshold=2) # Using 2 for demo purposes
    if not anomalies.empty:
        print(f"Found {len(anomalies)} Anomalies!")
        print(anomalies.head())
    else:
        print("No statistical anomalies found (Traffic is normal).")

    # 8. Visualization
    print("\n--- Generating Plots ---")
    plot_traffic_over_time(df)
    plot_protocol_distribution(df)
    plot_packet_size_hist(df)

if __name__ == "__main__":
    main()
