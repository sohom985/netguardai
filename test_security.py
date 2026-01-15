"""
test_security.py - Security Detection Test Tool
Injects fake attack packets into the database to test the security detection system.
"""
import sqlite3
from datetime import datetime

DB_FILE = "netguard.db"

def inject_sql_injection():
    """Inserts a fake SQL injection attack packet into the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    timestamp = datetime.now()
    protocol = "TCP"
    src_ip = "' OR '1'='1; DROP TABLE users; --"  # 🚨 SQL Injection!
    dst_ip = "192.168.1.1"
    length = 666
    
    cursor.execute(
        "INSERT INTO traffic (timestamp, protocol, src_ip, dst_ip, length) VALUES (?, ?, ?, ?, ?)",
        (timestamp, protocol, src_ip, dst_ip, length)
    )
    
    conn.commit()
    conn.close()
    print(f"🚨 Injected SQL Injection attack at {timestamp}")

def inject_xss():
    """Inserts a fake XSS attack packet into the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    timestamp = datetime.now()
    protocol = "TCP"
    src_ip = "<script>alert('XSS')</script>"  # ⚠️ XSS!
    dst_ip = "192.168.1.1"
    length = 420
    
    cursor.execute(
        "INSERT INTO traffic (timestamp, protocol, src_ip, dst_ip, length) VALUES (?, ?, ?, ?, ?)",
        (timestamp, protocol, src_ip, dst_ip, length)
    )
    
    conn.commit()
    conn.close()
    print(f"⚠️ Injected XSS attack at {timestamp}")

def clear_attacks():
    """Removes all fake attack packets from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM traffic WHERE src_ip LIKE '%DROP TABLE%'")
    cursor.execute("DELETE FROM traffic WHERE src_ip LIKE '%<script>%'")
    
    conn.commit()
    conn.close()
    print("🧹 Cleared all fake attack packets")

if __name__ == "__main__":
    print("Security Test Tool")
    print("1. Inject SQL Injection")
    print("2. Inject XSS")
    print("3. Clear all attacks")
    choice = input("Choose (1/2/3): ")
    
    if choice == "1":
        inject_sql_injection()
    elif choice == "2":
        inject_xss()
    elif choice == "3":
        clear_attacks()
    else:
        print("Invalid choice")
