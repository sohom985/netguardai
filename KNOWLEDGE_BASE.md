# 📚 NetGuardAI - Complete Knowledge Base

> **20-Hour Study Guide for Interview Preparation**
>
> **How to Read This File:**
>
> 1. **On Mac:** Open in VS Code or any text editor
> 2. **On Phone/Tablet:** Use "Markdown Viewer" apps (free):
>    - iOS: "iA Writer" or "Bear" (free) or just use Notes
>    - Android: "Markor" or "JotterPad" (free)
> 3. **In Browser:** Paste into <https://dillinger.io> for formatted view
> 4. **Quick Tip:** Send this file to yourself on Telegram/WhatsApp - it renders markdown!

---

# 📖 Table of Contents

| Section | Topics | Est. Time |
|---------|--------|-----------|
| Part 1 | Architecture & Core Concepts | 2 hours |
| Part 2 | Code Walkthrough (All Files) | 5 hours |
| Part 3 | Pandas Deep Dive | 4 hours |
| Part 4 | SQL & Database Concepts | 2 hours |
| Part 5 | Docker & Deployment | 2 hours |
| Part 6 | Security Concepts | 2 hours |
| Part 7 | Interview Q&A (50+ questions) | 3 hours |

**Total: ~20 hours of content!**

---

# Part 1: Architecture & Core Concepts (2 hours)

## 1.1 System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     NetGuardAI System                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│   │  sniffer.py  │───▶│  netguard.db │◀───│ dashboard.py │      │
│   │   (Capture)  │    │   (SQLite)   │    │  (Display)   │      │
│   └──────────────┘    └──────────────┘    └──────────────┘      │
│          │                   ▲                   │               │
│          │                   │                   │               │
│   Uses   ▼                   │           ┌──────▼──────┐        │
│   ┌──────────────┐           │           │security.py  │        │
│   │    Scapy     │           │           │(Detection)  │        │
│   │ (Raw Sockets)│           │           └─────────────┘        │
│   └──────────────┘           │                                   │
│                              │                                   │
│   Support Modules:           │                                   │
│   ┌─────────────────────────┴────────────────────────────────┐  │
│   │ data_loader.py • cleaning.py • features.py • analysis.py │  │
│   │ enrichment.py • visualizer.py                            │  │
│   └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│   Deployment: Docker + docker-compose                            │
└─────────────────────────────────────────────────────────────────┘
```

**Data Flow:**

1. `sniffer.py` captures network packets using Scapy
2. Packets are stored in `netguard.db` (SQLite database)
3. `dashboard.py` reads from database and displays in Streamlit
4. `security.py` scans for attack patterns
5. Support modules handle data processing

---

## 1.2 What is Packet Sniffing?

**The Basics:**
When you visit a website, your computer doesn't send one big message. It breaks data into small "packets" (typically 64-1500 bytes). Each packet has:

- **Header:** Source IP, Destination IP, Protocol, etc.
- **Payload:** The actual data (encrypted for HTTPS)

**Why Sniff Packets?**

1. **Network Monitoring:** See what's happening on your network
2. **Troubleshooting:** Find why something is slow/broken
3. **Security:** Detect attacks, unauthorized access
4. **Forensics:** Investigate after a breach

**The OSI Model (Interview Classic!):**

```
Layer 7: Application    (HTTP, SSH, DNS)      ← What apps use
Layer 6: Presentation   (SSL/TLS, Encryption) ← Format/Encrypt
Layer 5: Session        (Connections)         ← Session management
Layer 4: Transport      (TCP, UDP)            ← Ports, reliability
Layer 3: Network        (IP)                  ← IP addresses ← WE CAPTURE HERE
Layer 2: Data Link      (Ethernet, MAC)       ← Physical addressing
Layer 1: Physical       (Cables, WiFi)        ← Literal wires
```

**Interview Q: At which OSI layer does your sniffer operate?**
> "Layer 3 (Network). We capture IP packets, which includes source/destination IP addresses. We can also see Layer 4 information (TCP/UDP ports) but our current implementation focuses on Layer 3 metadata."

---

## 1.3 Why sudo is Required

**Technical Reason:**
Raw sockets (needed for packet capture) bypass the normal TCP/IP stack. This is powerful but dangerous - you could:

- See other users' traffic
- Forge packets pretending to be other machines
- Crash network services

**Security Model:**

```
Normal App:
    App → Operating System → Network Stack → Network
    (OS filters what you can see)

Raw Socket (sudo):
    App → Direct to Network Card
    (You see EVERYTHING)
```

**Interview Q: Could you make a web-based packet sniffer that works without sudo?**
> "No, and for good reason. If any website could capture network traffic, it would be a massive security vulnerability. Packet capture requires privileged access, which browsers cannot grant. That's why we use Docker with NET_RAW capability - the container is pre-authorized."

---

## 1.4 TCP vs UDP

**TCP (Transmission Control Protocol):**

- **Connection-oriented:** Handshake before data
- **Reliable:** Guarantees delivery, correct order
- **Slower:** Overhead for acknowledgments
- **Uses:** HTTP, SSH, Email, File Transfer

```
TCP Handshake:
Client → Server: SYN (Hey, want to talk?)
Server → Client: SYN-ACK (Sure, let's talk!)
Client → Server: ACK (Great, here's data...)
```

**UDP (User Datagram Protocol):**

- **Connectionless:** Just send, no handshake
- **Unreliable:** No guarantee of delivery
- **Faster:** No overhead
- **Uses:** DNS, Streaming, Gaming, VoIP

**Interview Q: Why do we capture both TCP and UDP?**
> "Different attacks use different protocols. DDoS often uses UDP (faster to flood). Command & control often uses TCP (reliable). DNS tunneling uses UDP. We need visibility into both to detect threats."

---

## 1.5 IP Address Basics

**IPv4 Format:**

```
192.168.1.100
 │   │   │  │
 │   │   │  └─ Host (0-255)
 │   │   └─── Subnet (0-255)
 │   └─────── Network Class (0-255)
 └─────────── Network Class (0-255)
```

**Private IP Ranges (Won't appear on public internet):**

| Range | Class | Typical Use |
|-------|-------|-------------|
| 10.0.0.0/8 | A | Large enterprises |
| 172.16.0.0/12 | B | Medium networks |
| 192.168.0.0/16 | C | Home networks |
| 127.0.0.0/8 | Loopback | localhost |

**Our Code Uses This:**

```python
def is_local_ip(ip):
    ip_obj = ipaddress.ip_address(ip)
    return ip_obj.is_private or ip_obj.is_loopback
```

---

# Part 2: Code Walkthrough - All Files (5 hours)

## 2.1 sniffer.py (The Heart of the System)

### Full Code with Annotations

```python
from scapy.all import sniff, IP, TCP, UDP
# Scapy: The premier Python packet manipulation library
# sniff: Function that captures packets from network interface
# IP, TCP, UDP: Layer parsers to decode packet contents

import sqlite3
# Built-in Python library for SQLite database
# No installation needed - comes with Python

import os
from datetime import datetime
# datetime: For timestamping each captured packet

DB_FILE = "netguard.db"
# Configuration: Database file path
# Using a constant makes it easy to change later
```

**Why Scapy?**

- Pure Python, cross-platform
- Can parse, forge, send, and sniff packets
- Understands 100+ protocols out of the box
- Alternative: `pypcap` (lower level, faster, harder to use)

```python
def init_db():
    """Creates the database and the table if they don't exist."""
    conn = sqlite3.connect(DB_FILE)
    # sqlite3.connect() opens OR creates the database file
    # If file exists, opens it. If not, creates it.
    
    cursor = conn.cursor()
    # A cursor is like a pointer in the database
    # We use it to execute SQL commands
    
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
    # CREATE TABLE IF NOT EXISTS: Idempotent - safe to run multiple times
    # PRIMARY KEY AUTOINCREMENT: Auto-generates unique IDs
    # We store: when, what protocol, from where, to where, how big
    
    conn.commit()
    # CRITICAL: Changes aren't saved until commit()!
    # Without this, your data disappears when connection closes
    
    conn.close()
    print(f"Database initialized: {DB_FILE}")
```

**Interview Q: What is SQL injection and how do you prevent it?**
> "SQL injection is when an attacker inserts malicious SQL code into input fields. For example, if I wrote `f"SELECT * FROM users WHERE name = '{input}'"` and someone entered `'; DROP TABLE users; --`, it would delete my table. I prevent this by NEVER using f-strings for SQL. Instead, I use parameterized queries with `?` placeholders: `cursor.execute('SELECT * FROM users WHERE name = ?', (input,))`. The database treats the input as data, never as SQL code."

```python
def packet_callback(packet):
    # This function is called by Scapy for EVERY packet captured
    # It runs in a loop, processing packets as fast as they arrive
    
    if IP in packet:
        # "IP in packet" checks if this is an IP packet
        # We ignore non-IP packets (ARP, etc.)
        
        src_ip = packet[IP].src   # Source IP address
        dst_ip = packet[IP].dst   # Destination IP address
        length = len(packet)       # Total packet size in bytes
        timestamp = datetime.now() # Current time
        
        # Determine the transport protocol
        protocol_name = "Other"
        if TCP in packet:
            protocol_name = "TCP"
        elif UDP in packet:
            protocol_name = "UDP"
        # Note: We could also check ICMP, GRE, etc.
        
        print(f"[{timestamp}] [{protocol_name}] {src_ip} -> {dst_ip} ({length} bytes)")
        # Visual feedback that the sniffer is working
        
        try:
            cursor = db_conn.cursor()
            cursor.execute(
                "INSERT INTO traffic (timestamp, protocol, src_ip, dst_ip, length) VALUES (?, ?, ?, ?, ?)",
                (timestamp, protocol_name, src_ip, dst_ip, length)
            )
            # The ? placeholders prevent SQL injection
            # Values are passed as a tuple (second argument)
            
            db_conn.commit()
            # Commit after each insert
            # Trade-off: Slower but safer (data saved immediately)
            # Alternative: Batch commits every N packets (faster but risk data loss)
        except Exception as e:
            print(f"DB Error: {e}")
            # Don't crash if database has an issue
            # Just log and continue capturing
```

**Performance Note:**
Committing after every packet is slow. In production, you'd batch:

```python
# Better performance version:
packet_buffer = []
BATCH_SIZE = 100

def packet_callback(packet):
    packet_buffer.append(packet_data)
    if len(packet_buffer) >= BATCH_SIZE:
        cursor.executemany("INSERT INTO...", packet_buffer)
        db_conn.commit()
        packet_buffer.clear()
```

```python
db_conn = None  # Global connection variable

def start_sniffing():
    global db_conn
    print("Initializing Database...")
    init_db()
    
    db_conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    # check_same_thread=False: Allows connection to be used across threads
    # Scapy's sniff() runs callback in different thread context
    
    print("Starting network sniffer... Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, store=0)
        # prn: "print function" - called for each packet
        # store=0: Don't store packets in memory (prevents memory leak)
        # Without store=0, memory usage grows until crash!
    finally:
        if db_conn:
            db_conn.close()
            print("DB Connection closed.")

if __name__ == "__main__":
    start_sniffing()
```

---

## 2.2 dashboard.py (The Web Interface)

```python
import streamlit as st
# Streamlit: Turn Python scripts into web apps
# No HTML/CSS/JS needed - just Python!

import sqlite3
import pandas as pd
import time
from security import scan_dataframe
# Import our security module for threat detection

st.set_page_config(
    page_title="NetGuardAI Dashboard",
    page_icon="🛡️",
    layout="wide"
)
# page_title: Browser tab title
# page_icon: Favicon (can be emoji or path to image)
# layout="wide": Use full browser width

st.title("🛡️ NetGuardAI - Real-Time Monitor")
# Creates <h1> heading with emoji
```

**Streamlit Magic:**

```python
# Normal Python:
print("Hello")  # Just prints to console

# Streamlit Python:
st.write("Hello")  # Creates HTML paragraph on web page!
```

```python
st.sidebar.header("Controls")
# st.sidebar: Creates a collapsible sidebar
# Great for controls, filters, navigation

use_live_mode = st.sidebar.checkbox("🔴 Live Monitoring Mode")
# Returns True/False based on checkbox state
# Streamlit reruns ENTIRE script when value changes!

if st.sidebar.button("Refresh Now 🔄"):
    st.rerun()
# Button returns True only when clicked
# st.rerun() forces page refresh

st.sidebar.write(f"Last Update: {time.strftime('%H:%M:%S')}")
# Shows current time in sidebar
```

```python
@st.cache_data(ttl=3)
def load_data():
    """Loads data from database with caching."""
    # @st.cache_data: Memoization decorator
    # ttl=3: "Time to Live" - cache expires after 3 seconds
    # Without this, every button click reloads entire database!
    
    try:
        conn = sqlite3.connect("netguard.db", timeout=5)
        # timeout=5: Wait up to 5 seconds if DB is locked
        # Prevents crash if sniffer is writing
        
        df = pd.read_sql(
            "SELECT * FROM traffic ORDER BY id DESC LIMIT 500",
            conn
        )
        # ORDER BY id DESC: Newest first
        # LIMIT 500: Only load recent data (performance!)
        
        conn.close()
        
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        # Convert string to datetime for proper sorting/charting
        
        return df
    except Exception as e:
        st.error(f"DB Error: {e}")
        return pd.DataFrame()  # Return empty DataFrame on error
```

**Understanding @st.cache_data:**

```
First call: load_data() runs → result cached
Next 3 seconds: load_data() returns cached result (instant!)
After 3 seconds: Cache expires, load_data() runs again

Benefits:
1. Faster page interactions
2. Less database load
3. Smoother user experience
```

```python
df = load_data()

if df.empty:
    st.warning("⚠️ No data found! Please run 'sniffer.py'")
else:
    # KPI Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    # Creates 4 equal-width columns for layout
    
    col1.metric("Total Packets", len(df))
    col2.metric("Unique Sources", df['src_ip'].nunique())
    col3.metric("Protocols", df['protocol'].nunique())
    col4.metric("Avg Packet Size", f"{df['length'].mean():.0f} bytes")
    # .metric() creates a big number with label - great for KPIs
    # :.0f means format as float with 0 decimal places
```

**Pandas Operations Explained:**

```python
len(df)                    # Number of rows
df['src_ip'].nunique()     # Number of UNIQUE values (distinct IPs)
df['protocol'].nunique()   # Number of unique protocols (usually 2-3)
df['length'].mean()        # Average of all values in column
```

```python
    st.subheader("📡 Live Traffic Feed")
    st.dataframe(df.head(20), use_container_width=True)
    # st.dataframe(): Interactive table (sortable, scrollable)
    # .head(20): Only show first 20 rows
    # use_container_width=True: Stretch to fill page width
```

```python
    # Charts Section
    st.markdown("---")  # Horizontal line separator
    st.subheader("📊 Traffic Analytics")
    
    chart1, chart2 = st.columns(2)  # Two-column layout
    
    with chart1:
        st.write("**Protocol Distribution**")
        if 'protocol' in df.columns:
            st.bar_chart(df['protocol'].value_counts())
            # value_counts(): Counts occurrences of each value
            # Returns Series: {'TCP': 350, 'UDP': 120, 'Other': 30}
            # st.bar_chart(): Renders as bar chart automatically
    
    with chart2:
        st.write("**Packet Sizes**")
        if 'length' in df.columns:
            st.bar_chart(df['length'].head(50))
            # Shows packet sizes of most recent 50 packets
```

```python
    # Security Section
    st.markdown("---")
    st.subheader("🛡️ Security Threat Detection")
    
    df_scanned = scan_dataframe(df)
    # Calls our security module to check for attacks
    # Returns same DataFrame with 'threat_type' column added
    
    threats = df_scanned[df_scanned['threat_type'] != 'Normal']
    # Filter to only rows where threat was detected
    # Boolean indexing: df[condition]
    
    if len(threats) > 0:
        st.error(f"⚠️ Detected {len(threats)} suspicious packets!")
        st.dataframe(
            threats[['timestamp', 'src_ip', 'dst_ip', 'threat_type']],
            use_container_width=True
        )
    else:
        st.success("✅ No attack patterns detected in current traffic.")

# Live Mode (Must be at end!)
if use_live_mode:
    time.sleep(3)  # Wait 3 seconds
    st.rerun()     # Refresh the page
    # Creates auto-refresh effect
    # Warning: This reloads EVERYTHING - use sparingly
```

---

## 2.3 security.py (Attack Detection)

```python
import re
# Regular expressions for pattern matching
# Most powerful text search/matching in Python

SQL_INJECTION_PATTERNS = [
    r"('\s*OR\s*'1'\s*=\s*'1)",   # Classic OR 1=1
    r"(;\s*DROP\s+TABLE)",        # Drop table attack
    r"(UNION\s+SELECT)",          # Union-based injection
    r"(--\s*$)",                   # SQL comment
    r"('\s*;\s*--)",               # End query, start comment
    r"(EXEC\s*\()",                # Execute command
    r"(xp_cmdshell)",              # SQL Server command shell
]
```

**Regex Breakdown:**

```
r"('\s*OR\s*'1'\s*=\s*'1)"

r"..."     - Raw string (backslashes are literal)
'          - Match a single quote
\s*        - Zero or more whitespace characters
OR         - Literal text "OR"
'1'        - Literal '1'
=          - Literal equals sign

Pattern matches: ' OR '1'='1    (the classic SQL injection)
```

```python
XSS_PATTERNS = [
    r"(<script.*?>)",      # Script tags
    r"(javascript:)",      # JavaScript URLs
    r"(onerror\s*=)",      # Error handlers
    r"(onload\s*=)",       # Load handlers
]
# XSS = Cross-Site Scripting
# Attacker injects JavaScript into web pages
```

```python
def detect_sql_injection(text):
    """Check if text contains SQL injection patterns."""
    if not text:
        return []  # Empty input = no matches
    
    matches = []
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, str(text), re.IGNORECASE):
            # re.search: Find pattern anywhere in string
            # re.IGNORECASE: Match regardless of case
            matches.append(pattern)
    return matches

def scan_dataframe(df):
    """Scan entire DataFrame for attack patterns."""
    df = df.copy()  # Don't modify original!
    df['threat_type'] = 'Normal'  # Default: no threat
    
    text_cols = ['src_ip', 'dst_ip', 'protocol']
    # Columns that might contain attack strings
    
    for idx, row in df.iterrows():
        # iterrows(): Loop through each row
        # idx = row number, row = Series with column values
        
        for col in text_cols:
            if col in df.columns:
                val = str(row.get(col, ''))
                
                if detect_sql_injection(val):
                    df.at[idx, 'threat_type'] = '🚨 SQL Injection'
                    # df.at[idx, col]: Set value at specific cell
                elif detect_xss(val):
                    df.at[idx, 'threat_type'] = '⚠️ XSS'
    
    return df
```

**Interview Q: Why scan IP addresses for SQL injection?**
> "In a real scenario, HTTP payloads would be captured too. Our simplified version demonstrates the concept. In production, you'd dump and analyze packet payloads, not just metadata. The same detection logic applies - just different data source."

---

## 2.4 data_loader.py

```python
import sqlite3
import pandas as pd

def load_traffic_data(db_path):
    """Load traffic data efficiently."""
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        # timeout=5: If database is locked, wait 5 seconds before error
        # Why locked? sniffer.py might be writing at this moment
        
        df = pd.read_sql(
            "SELECT * FROM traffic ORDER BY timestamp DESC LIMIT 2000",
            conn
        )
        # ORDER BY timestamp DESC: Newest first
        # LIMIT 2000: Cap the data to prevent memory issues
        
        df = df.sort_values('timestamp')
        # Re-sort to chronological for proper visualization
        # We loaded newest first, now oldest→newest for charts
        
        conn.close()
        return df
        
    except Exception as e:
        print(f"Error loading data: {e}")
        return pd.DataFrame()  # Empty DataFrame on error
```

**Why LIMIT?**

| Database Size | Without LIMIT | With LIMIT 2000 |
|---------------|---------------|-----------------|
| 100 rows | 0.01s | 0.01s |
| 10,000 rows | 0.5s | 0.02s |
| 1,000,000 rows | 30s (crash?) | 0.02s |

---

## 2.5 cleaning.py

```python
import pandas as pd

def clean_timestamps(df):
    """Convert timestamp strings to datetime objects."""
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df
```

**Why Convert Types?**

```python
# String timestamp:
"2024-01-15 10:30:00"  # Just text - can't do math

# Datetime object:
pd.to_datetime("2024-01-15 10:30:00")  # Now you can:
# - Add/subtract time: ts + timedelta(hours=1)
# - Extract parts: ts.hour, ts.dayofweek
# - Resample: df.resample('1s')
```

```python
def parse_ips(df):
    """Extract IP metadata."""
    if 'src_ip' in df.columns:
        df['first_octet'] = df['src_ip'].str.split('.').str[0]
        # Chain: .str.split('.') → ['192', '168', '1', '1']
        #        .str[0]        → '192'
        
        df['is_local'] = df['src_ip'].str.startswith('192')
        # Returns True/False for each row
    return df
```

```python
def optimize_memory(df):
    """Convert strings to categories for memory efficiency."""
    for col in ['protocol', 'src_ip', 'dst_ip']:
        if col in df.columns and df[col].dtype == 'object':
            df[col] = df[col].astype('category')
    return df
```

**Memory Comparison:**

```python
# 'object' dtype (strings):
['TCP', 'UDP', 'TCP', 'TCP', 'UDP'] × 10000 rows
= 10000 string pointers = ~800KB

# 'category' dtype:
Codes: [0, 1, 0, 0, 1] × 10000 = 10000 integers = ~40KB
Categories: ['TCP', 'UDP'] = 2 strings = ~40 bytes
Total = ~41KB

Savings: 95%!
```

---

## 2.6 features.py (ML Preparation)

```python
def add_time_series_features(df):
    """Create features for machine learning."""
    df = df.sort_values('timestamp')  # Ensure chronological order
    
    # Rolling Average: Smooth out noise
    df['rolling_avg_len'] = df['length'].rolling(window=5).mean()
```

**What is Rolling Average?**

```
Raw data:      [100, 200, 50, 300, 150, 100, 250]
                                 ↓
Rolling(5):    [NaN, NaN, NaN, NaN, 160, 160, 170]
               (Need 5 values before first calculation)
               
Packet 5: (100+200+50+300+150)/5 = 160
Packet 6: (200+50+300+150+100)/5 = 160
Packet 7: (50+300+150+100+250)/5 = 170
```

**Why Use It?**

- Smooths out random variation
- Helps ML models see trends
- Common in time series analysis

```python
    # Expanding Sum: Running total
    df['running_total_bytes'] = df['length'].expanding().sum()
```

**Expanding vs Rolling:**

```
Data:       [100, 200, 150, 50]

Rolling(2): [NaN, 150, 175, 100]  # Window moves
Expanding:  [100, 300, 450, 500]  # Window grows
```

```python
    # Lag Features: Previous values
    df['prev_length'] = df['length'].shift(1)
```

**What is Shift?**

```
Original: [100, 200, 150, 50]
Shift(1): [NaN, 100, 200, 150]  # Each value moves down 1 row
Shift(-1):[200, 150, 50, NaN]   # Each value moves up 1 row
```

**Why Lag Features?**
ML models can learn patterns like:

- "If previous packet was large, next is usually small"
- "Bursts of small packets often precede large ones"

```python
    # One-Hot Encoding: Convert categories to numbers
    dummies = pd.get_dummies(df['protocol'], prefix='proto', dtype=int)
    df = pd.concat([df, dummies], axis=1)
```

**Why One-Hot Encode?**

```
ML algorithms need numbers!

Before: protocol = ['TCP', 'UDP', 'TCP']
After:  proto_TCP = [1, 0, 1]
        proto_UDP = [0, 1, 0]
```

```python
    # Time Difference: Seconds between packets
    df['time_diff'] = df['timestamp'].diff().dt.total_seconds().fillna(0.0)
    
    # Byte Rate: Bytes per second
    df['byte_rate'] = df['length'] / (df['time_diff'] + 0.001)
    # + 0.001: Prevent division by zero!
    
    return df
```

---

## 2.7 analysis.py

```python
def get_basic_stats(df):
    """Get descriptive statistics."""
    return df['length'].describe()
    # Returns: count, mean, std, min, 25%, 50%, 75%, max
```

```python
def get_top_talkers(df, n=5):
    """Find IPs sending most packets."""
    return df['src_ip'].value_counts().head(n)
    # value_counts(): Count occurrences
    # head(n): Top N results
```

```python
def detect_zscore_anomalies(df, threshold=3):
    """Find anomalies using Z-Score method."""
    mu = df['length'].mean()     # Average
    sigma = df['length'].std()   # Standard deviation
    
    df = df.copy()
    df['z_score'] = (df['length'] - mu) / sigma
    # Z = (value - mean) / stddev
    # Measures "how unusual" each value is
    
    anomalies = df[abs(df['z_score']) > threshold]
    # Keep only rows where |Z| > threshold
    # threshold=3 means 99.7% of normal data excluded
    
    return anomalies[['timestamp', 'src_ip', 'length', 'z_score']]
```

**Z-Score Intuition:**

```
Mean = 500 bytes, StdDev = 100 bytes

Packet Size | Z-Score | Interpretation
------------|---------|---------------
500 bytes   | 0       | Perfectly average
600 bytes   | 1       | Slightly larger than normal
700 bytes   | 2       | Unusual (top 5%)
800 bytes   | 3       | Very unusual (top 0.3%) ← ANOMALY
1500 bytes  | 10      | Extremely anomalous
```

---

## 2.8 enrichment.py (IP Geolocation)

```python
import requests
import ipaddress
import time

def is_local_ip(ip):
    """Check if IP is private/local."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        return False  # Invalid IP format
```

```python
def get_ip_info(ip):
    """Fetch geolocation data from API."""
    if is_local_ip(ip):
        return {
            'ip': ip,
            'country': 'Local Network',
            'city': 'Local',
            'isp': 'Local Device',
            'threat_level': 'Safe'
        }
    
    try:
        time.sleep(1.5)  # Rate limiting: 45 req/min allowed
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )
        data = response.json()
        
        if data['status'] == 'success':
            return {
                'ip': ip,
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'threat_level': 'Public'
            }
    except Exception as e:
        print(f"API Error: {e}")
    
    return {'ip': ip, 'country': 'Unknown', ...}
```

**Interview Q: How do you handle API rate limits?**
> "I added a 1.5-second sleep between requests to stay under ip-api's 45/minute limit. For production, I'd implement: 1) Caching results to avoid re-requesting same IPs, 2) Exponential backoff if rate limited, 3) Multiple API providers for redundancy."

---

# Part 3: Pandas Deep Dive (4 hours)

## 3.1 DataFrame Fundamentals

**Creating DataFrames:**

```python
# From dictionary:
df = pd.DataFrame({
    'name': ['Alice', 'Bob'],
    'age': [25, 30]
})

# From list of dictionaries:
df = pd.DataFrame([
    {'name': 'Alice', 'age': 25},
    {'name': 'Bob', 'age': 30}
])

# From SQL:
df = pd.read_sql("SELECT * FROM table", connection)

# From CSV:
df = pd.read_csv("file.csv")
```

**Viewing Data:**

```python
df.head(5)      # First 5 rows
df.tail(5)      # Last 5 rows
df.sample(5)    # Random 5 rows
df.shape        # (rows, columns) tuple
df.columns      # Column names
df.dtypes       # Data types per column
df.info()       # Summary of DataFrame
df.describe()   # Statistics for numeric columns
```

---

## 3.2 Selection & Filtering

**Column Selection:**

```python
df['column']        # Returns Series
df[['col1', 'col2']]  # Returns DataFrame with 2 columns
```

**Row Selection:**

```python
df.loc[0]           # Row by label/index
df.iloc[0]          # Row by position
df.loc[0:5]         # Rows 0-5 by label
df.iloc[0:5]        # Rows 0-5 by position
```

**Boolean Filtering:**

```python
df[df['age'] > 25]                      # Age greater than 25
df[df['name'] == 'Alice']               # Name is Alice
df[(df['age'] > 25) & (df['age'] < 35)] # Between 25-35
df[df['name'].isin(['Alice', 'Bob'])]   # In list
df[df['name'].str.contains('Ali')]      # Contains string
```

**The .query() Method:**

```python
# Equivalent ways to filter:
df[df['age'] > 25]
df.query('age > 25')  # More readable for complex conditions
df.query('age > 25 and name == "Alice"')
```

---

## 3.3 GroupBy Operations

**Basic GroupBy:**

```python
# Count packets per protocol
df.groupby('protocol').size()

# Average length per protocol
df.groupby('protocol')['length'].mean()

# Multiple aggregations
df.groupby('protocol').agg({
    'length': ['mean', 'sum', 'max'],
    'id': 'count'
})
```

**Transform vs Aggregate:**

```python
# Aggregate: Returns one value per group
df.groupby('protocol')['length'].mean()
# Returns: TCP: 500, UDP: 200

# Transform: Returns same-length Series
df.groupby('protocol')['length'].transform('mean')
# Returns: [500, 200, 500, 500, 200, ...] for each row
# Useful for calculating "difference from group mean"
```

---

## 3.4 Time Series Operations

**Resampling:**

```python
# Set timestamp as index
df = df.set_index('timestamp')

# Count packets per second
df.resample('1s').size()

# Average length per minute
df.resample('1min')['length'].mean()

# Sum bytes per hour
df.resample('1H')['length'].sum()
```

**Resampling Rules:**

| Rule | Meaning |
|------|---------|
| 's' | Second |
| 'min' | Minute |
| 'H' | Hour |
| 'D' | Day |
| 'W' | Week |
| 'M' | Month |

---

## 3.5 Merging & Joining

**Merge (like SQL JOIN):**

```python
# Inner join (only matching rows)
pd.merge(df1, df2, on='key')

# Left join (all from df1, matching from df2)
pd.merge(df1, df2, on='key', how='left')

# Outer join (all rows from both)
pd.merge(df1, df2, on='key', how='outer')

# Different column names
pd.merge(df1, df2, left_on='col1', right_on='col2')
```

**Concat (stack DataFrames):**

```python
# Stack vertically (add rows)
pd.concat([df1, df2], axis=0)

# Stack horizontally (add columns)
pd.concat([df1, df2], axis=1)
```

---

# Part 4: SQL & Database (2 hours)

## 4.1 SQLite Basics

**Creating Tables:**

```sql
CREATE TABLE traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME,
    protocol TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    length INTEGER
);
```

**Inserting Data:**

```sql
INSERT INTO traffic (timestamp, protocol, src_ip, dst_ip, length)
VALUES ('2024-01-15 10:30:00', 'TCP', '192.168.1.1', '8.8.8.8', 500);
```

**Selecting Data:**

```sql
-- All rows
SELECT * FROM traffic;

-- Specific columns
SELECT timestamp, src_ip FROM traffic;

-- With filter
SELECT * FROM traffic WHERE protocol = 'TCP';

-- With sorting
SELECT * FROM traffic ORDER BY timestamp DESC;

-- With limit
SELECT * FROM traffic LIMIT 100;
```

**Aggregations:**

```sql
SELECT protocol, COUNT(*) as count, AVG(length) as avg_size
FROM traffic
GROUP BY protocol;
```

---

## 4.2 Python + SQLite

```python
import sqlite3

# Connect (creates file if not exists)
conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# Execute SQL
cursor.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER, name TEXT)")

# Insert with parameters (SAFE from injection)
cursor.execute("INSERT INTO test VALUES (?, ?)", (1, "Alice"))

# Fetch results
cursor.execute("SELECT * FROM test")
rows = cursor.fetchall()  # List of tuples

# Pandas integration
import pandas as pd
df = pd.read_sql("SELECT * FROM test", conn)

# Clean up
conn.commit()  # Save changes
conn.close()   # Close connection
```

---

# Part 5: Docker (2 hours)

## 5.1 Core Concepts

**Image vs Container:**

- **Image:** Template/blueprint (like a class)
- **Container:** Running instance (like an object)

**Dockerfile Breakdown:**

```dockerfile
FROM python:3.11-slim
# Start from official Python image

WORKDIR /app
# All future commands run from /app

COPY requirements.txt .
# Copy just requirements first

RUN pip install -r requirements.txt
# Install dependencies (cached if requirements unchanged)

COPY . .
# Copy rest of code

EXPOSE 8501
# Document which port the app uses

CMD ["./entrypoint.sh"]
# Default command when container starts
```

**docker-compose.yml:**

```yaml
services:
  netguardai:
    build: .                    # Build from Dockerfile in current dir
    container_name: netguardai  # Name for the container
    cap_add:                    # Add Linux capabilities
      - NET_RAW                 # Raw socket access
      - NET_ADMIN               # Network configuration
    network_mode: host          # Share host's network
    volumes:
      - ./netguard.db:/app/netguard.db  # Persist database
    restart: unless-stopped     # Auto-restart if crashed
```

---

## 5.2 Common Commands

```bash
# Build image
docker build -t myapp .

# Run container
docker run -d --name myapp myapp

# View running containers
docker ps

# View logs
docker logs myapp

# Stop container
docker stop myapp

# Remove container
docker rm myapp

# Docker Compose commands
docker-compose up -d      # Start (detached)
docker-compose down       # Stop and remove
docker-compose logs       # View logs
docker-compose restart    # Restart
```

---

# Part 6: Security Concepts (2 hours)

## 6.1 SQL Injection

**Vulnerable Code:**

```python
# NEVER DO THIS!
query = f"SELECT * FROM users WHERE name = '{user_input}'"
```

**Attack:**

```
Input: ' OR '1'='1
Query: SELECT * FROM users WHERE name = '' OR '1'='1'
Result: Returns ALL users!
```

**More Dangerous:**

```
Input: '; DROP TABLE users; --
Query: SELECT * FROM users WHERE name = ''; DROP TABLE users; --'
Result: Database destroyed!
```

**Prevention:**

```python
# Always use parameterized queries
cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
```

---

## 6.2 XSS (Cross-Site Scripting)

**How It Works:**

1. Attacker injects: `<script>stealCookies()</script>`
2. Website stores it in database
3. Other users load page, script executes
4. Attacker gets their cookies/passwords

**Prevention:**

- Escape HTML: `<` becomes `&lt;`
- Content Security Policy headers
- HttpOnly cookies (JavaScript can't access)

---

## 6.3 Network Attack Types

| Attack | How It Works | Detection |
|--------|--------------|-----------|
| DDoS | Flood with traffic | Unusual volume spike |
| Port Scan | Probe many ports | Many connections to different ports |
| Brute Force | Try many passwords | Many failed logins |
| MITM | Intercept traffic | Unusual routing, cert errors |

---

# Part 7: Interview Q&A (3 hours)

## General Project Questions

**Q: Explain your project in 30 seconds.**
> "NetGuardAI is a real-time network traffic analyzer with AI-powered threat detection. It captures packets using Scapy, stores them in SQLite, and provides a Streamlit dashboard showing traffic metrics, protocol distribution, and security alerts. I containerized it with Docker for easy deployment."

**Q: What makes your project stand out?**
> "It's end-to-end: raw packet capture to threat detection to visualization. I solved real production challenges like database locking, memory optimization, and live dashboard updates. And it's containerized for one-command deployment."

**Q: What was the hardest bug?**
> "The dashboard kept freezing. I traced it to SQLite locking during writes. Solution: WAL mode, connection timeout, and persistent database connection in the sniffer. Dashboard went from frozen to instant."

**Q: How would you scale this?**
> "Three changes: 1) PostgreSQL for multi-user access, 2) Apache Kafka for packet streaming, 3) Kubernetes for horizontal scaling."

---

## Technical Questions

**Q: Why Scapy instead of tcpdump?**
> "Scapy provides a Python API for packet manipulation. I can parse layers, extract fields, and forge packets for testing. tcpdump is text-based and requires output parsing."

**Q: Why SQLite?**
> "For a single-machine monitor, SQLite needs no server, has zero config, and stores everything in one portable file. For multi-user, I'd use PostgreSQL."

**Q: Explain your anomaly detection.**
> "I use Z-score: calculate how many standard deviations each value is from the mean. Threshold of 3 catches the 0.3% most extreme values. It's simple, fast, and effective for packet size anomalies."

**Q: What ML model would you add?**
> "Isolation Forest for unsupervised anomaly detection - no labels needed. For classification, Random Forest on CICIDS2017 labeled attack dataset."

---

## Security Questions

**Q: How do you prevent SQL injection?**
> "Parameterized queries with `?` placeholders. User input is data, never SQL code."

**Q: What attacks can you detect?**
> "SQL injection and XSS via regex pattern matching. Statistical anomalies via Z-score. With ML: DDoS, port scans, brute force."

**Q: Is your dashboard vulnerable?**
> "Streamlit handles input sanitization. Our SQLite queries use parameters. The main risk is if someone gains shell access to the server running the sniffer."

---

## Pandas Questions

**Q: df.apply() vs vectorization?**
> "Vectorized operations are 10-100x faster. They use NumPy's C implementation. apply() runs Python code per row. Use vectorization whenever possible."

**Q: How do you handle memory with large data?**
> "Three strategies: 1) Categorical dtype for repeated strings (75% savings), 2) Chunked reading with pd.read_csv(chunksize=N), 3) Query database with LIMIT instead of loading everything."

**Q: Explain groupby-transform.**
> "groupby().agg() returns one row per group. groupby().transform() returns original-length Series. Transform is useful for adding group statistics as a new column without changing row count."

---

## Docker Questions

**Q: Explain your Dockerfile.**
> "FROM python:3.11-slim for minimal base. COPY requirements first for layer caching. RUN pip install for dependencies. COPY code. EXPOSE port. CMD for startup."

**Q: Why cap_add: NET_RAW?**
> "Raw sockets need Linux capabilities. NET_RAW allows raw socket access for packet capture. Without it, Scapy can't sniff."

**Q: Image vs Container?**
> "Image is the template (like a class). Container is a running instance (like an object). One image can spawn many containers."

---

# Quick Reference: Commands

```bash
# Start system
docker-compose up -d

# Stop system
docker-compose down

# View logs
docker logs netguardai

# Manual start
./run_netguard.sh

# Test security
python test_security.py

# Forge packets
sudo python packet_forger.py
```

---

**You've got 20 hours of material here. You're going to crush that interview!** 🚀

Remember: Interviewers love when you explain WHY, not just WHAT. Always explain the reasoning!

Safe travels! ✈️
