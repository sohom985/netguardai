from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import os
from datetime import datetime

# 1. SETUP THE DATABASE
# We create a file named 'netguard.db'. This is our SQL database.
DB_FILE = "netguard.db"

def init_db():
    """Creates the database and the table if they don't exist."""
    # Connect to the database (it creates the file if it doesn't exist)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create a Table named 'traffic'.
    # Think of this like a spreadsheet with columns: id, timestamp, protocol, src_ip, dst_ip, length
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            protocol TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            length INTEGER
        )
    ''')
    
    # Save changes and close
    conn.commit()
    conn.close()
    print(f"Database initialized: {DB_FILE}")

def packet_callback(packet):
    # We only care about IP packets
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)
        timestamp = datetime.now()
        
        # Determine protocol
        protocol_name = "Other"
        if TCP in packet:
            protocol_name = "TCP"
        elif UDP in packet:
            protocol_name = "UDP"

        # Print to console (so we know it's working)
        print(f"[{timestamp}] [{protocol_name}] {src_ip} -> {dst_ip} ({length} bytes)")

        # 2. SAVE TO SQL
        # Use the global connection (much faster!)
        try:
            cursor = db_conn.cursor()
            cursor.execute("INSERT INTO traffic (timestamp, protocol, src_ip, dst_ip, length) VALUES (?, ?, ?, ?, ?)",
                           (timestamp, protocol_name, src_ip, dst_ip, length))
            db_conn.commit()
        except Exception as e:
            print(f"DB Error: {e}")

# Global DB Connection
db_conn = None

def start_sniffing():
    global db_conn
    print("Initializing Database...")
    init_db()
    # Keep connection open!
    db_conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    
    print("Starting network sniffer... Press Ctrl+C to stop.")
    # Real Mode: Capture forever (count=0) and don't store in RAM (store=0)
    try:
        sniff(prn=packet_callback, store=0)
    finally:
        if db_conn:
            db_conn.close()
            print("DB Connection closed.")
    print("Initializing Database...")
    init_db()
    
    print("Starting network sniffer... Press Ctrl+C to stop.")
    # Real Mode: Capture forever (count=0) and don't store in RAM (store=0)
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
