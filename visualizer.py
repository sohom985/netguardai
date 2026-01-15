import pandas as pd
import matplotlib.pyplot as plt

def plot_traffic_over_time(df, filename="traffic_over_time.png"):
    """
    Plots the number of packets per second.
    """
    if 'timestamp' not in df.columns:
        return
        
    # Resample to get count per second
    df_plot = df.set_index('timestamp').resample('1s').size()
    
    plt.figure(figsize=(10, 5))
    df_plot.plot(kind='line', marker='o', color='green')
    plt.title("Network Traffic Volume (Packets/Sec)")
    plt.xlabel("Time")
    plt.ylabel("Packets")
    plt.grid(True)
    plt.savefig(filename)
    print(f"Plot saved: {filename}")
    plt.close()

def plot_protocol_distribution(df, filename="protocol_dist.png"):
    """
    Plots a pie chart of protocol usage.
    """
    if 'protocol' not in df.columns:
        return
        
    plt.figure(figsize=(7, 7))
    df['protocol'].value_counts().plot(kind='pie', autopct='%1.1f%%', startangle=90)
    plt.title("Protocol Distribution")
    plt.ylabel("") # Hide the "protocol" label on the side
    plt.savefig(filename)
    print(f"Plot saved: {filename}")
    plt.close()

def plot_packet_size_hist(df, filename="packet_size_hist.png"):
    """
    Plots a histogram of packet sizes.
    """
    plt.figure(figsize=(10, 5))
    df['length'].plot(kind='hist', bins=20, color='purple', alpha=0.7)
    plt.title("Packet Size Distribution")
    plt.xlabel("Bytes")
    plt.ylabel("Frequency")
    plt.savefig(filename)
    print(f"Plot saved: {filename}")
    plt.close()