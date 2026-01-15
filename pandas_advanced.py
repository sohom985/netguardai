"""
pandas_advanced.py - Advanced Pandas Techniques
Phase 5.2: Pivoting, Melting, Hierarchical Reshaping
Phase 6.3: Large Datasets (Parquet, Arrow, Lazy Loading)
"""
import pandas as pd
import sqlite3
import numpy as np

print("=" * 60)
print("📊 Advanced Pandas Techniques - Learning Module")
print("=" * 60)

# ============================================================
# PHASE 5.2: Pivoting, Melting, Hierarchical Reshaping
# ============================================================

print("\n" + "=" * 60)
print("PHASE 5.2: Pivoting, Melting, Hierarchical Reshaping")
print("=" * 60)

# Load sample data
conn = sqlite3.connect('netguard.db')
df = pd.read_sql("SELECT * FROM traffic LIMIT 100", conn)
conn.close()

print("\n📌 Original Data Shape:", df.shape)
print(df.head(3))

# -----------------------------
# 1. PIVOT TABLE
# -----------------------------
print("\n" + "-" * 40)
print("1. PIVOT TABLE")
print("-" * 40)
print("""
What is a Pivot Table?
- Reshapes data from "long" to "wide" format
- Like Excel pivot tables!
- Groups data by rows AND columns

Example: Average packet length by Protocol AND Source IP
""")

pivot_example = df.pivot_table(
    values='length',           # What to aggregate
    index='src_ip',            # Row labels
    columns='protocol',        # Column labels
    aggfunc='mean',            # Aggregation function
    fill_value=0               # What to put for missing combinations
)

print("Pivot Table (Avg Length by IP x Protocol):")
print(pivot_example.head())

# -----------------------------
# 2. MELT (Opposite of Pivot)
# -----------------------------
print("\n" + "-" * 40)
print("2. MELT (Unpivot)")
print("-" * 40)
print("""
What is Melt?
- Reshapes data from "wide" to "long" format
- Opposite of pivot!
- Creates 'variable' and 'value' columns

Example: Turn our pivot table BACK to long format
""")

# First let's create a wide dataframe
wide_df = pd.DataFrame({
    'src_ip': ['192.168.1.1', '192.168.1.2'],
    'TCP_packets': [100, 150],
    'UDP_packets': [50, 75]
})
print("Wide format:")
print(wide_df)

# Now melt it to long format
melted = pd.melt(
    wide_df,
    id_vars=['src_ip'],              # Keep this column as-is
    value_vars=['TCP_packets', 'UDP_packets'],  # Melt these columns
    var_name='protocol_type',         # Name for variable column
    value_name='packet_count'         # Name for value column
)
print("\nMelted to long format:")
print(melted)

# -----------------------------
# 3. STACK & UNSTACK
# -----------------------------
print("\n" + "-" * 40)
print("3. STACK & UNSTACK")
print("-" * 40)
print("""
What is Stack/Unstack?
- Stack: Move column index to row index (column → row)
- Unstack: Move row index to column index (row → column)
- Works with MultiIndex DataFrames

Example: Using our pivot table
""")

# Our pivot table already has MultiIndex-like structure
print("Original pivot table:")
print(pivot_example.head(3))

# Stack: columns become rows
stacked = pivot_example.head(3).stack()
print("\nStacked (columns → rows):")
print(stacked)

# Unstack: rows become columns
unstacked = stacked.unstack()
print("\nUnstacked (rows → columns) - back to original:")
print(unstacked)

# -----------------------------
# 4. HIERARCHICAL INDEX (MultiIndex)
# -----------------------------
print("\n" + "-" * 40)
print("4. HIERARCHICAL RESHAPING with MultiIndex")
print("-" * 40)

# Create a MultiIndex DataFrame
multi_df = df.groupby(['protocol', 'src_ip']).agg({
    'length': ['count', 'mean', 'max']
}).head(6)

print("MultiIndex DataFrame:")
print(multi_df)

# Access with .xs() (cross-section)
print("\nCross-section for TCP only:")
try:
    tcp_only = multi_df.xs('TCP', level='protocol')
    print(tcp_only.head(3))
except:
    print("(TCP data not available in sample)")

# Flatten MultiIndex columns
multi_df.columns = ['_'.join(col).strip() for col in multi_df.columns.values]
print("\nFlattened column names:")
print(multi_df.head(3))


# ============================================================
# PHASE 6.3: Large Datasets (Parquet, Arrow, Lazy Loading)
# ============================================================

print("\n" + "=" * 60)
print("PHASE 6.3: Large Datasets (Parquet, Arrow, Lazy Loading)")
print("=" * 60)

# -----------------------------
# 1. PARQUET FORMAT
# -----------------------------
print("\n" + "-" * 40)
print("1. PARQUET FORMAT")
print("-" * 40)
print("""
What is Parquet?
- Column-oriented storage format
- Highly compressed (50-90% smaller than CSV!)
- MUCH faster to read than CSV
- Perfect for big data

Why use Parquet?
- 100MB CSV → 10-20MB Parquet
- Read time: seconds instead of minutes
- Only reads columns you need (columnar!)
""")

# Save data as Parquet
parquet_file = "traffic_sample.parquet"
df.to_parquet(parquet_file, engine='pyarrow')
print(f"\n✅ Saved {len(df)} rows to {parquet_file}")

# Read it back
df_parquet = pd.read_parquet(parquet_file)
print(f"✅ Read back {len(df_parquet)} rows from Parquet")

# Read only specific columns (EFFICIENT!)
df_partial = pd.read_parquet(parquet_file, columns=['src_ip', 'length'])
print(f"✅ Read only 2 columns: {df_partial.columns.tolist()}")

# -----------------------------
# 2. ARROW (PyArrow)
# -----------------------------
print("\n" + "-" * 40)
print("2. ARROW (PyArrow)")
print("-" * 40)
print("""
What is Apache Arrow?
- In-memory columnar format
- ZERO-COPY reads (incredibly fast!)
- Native integration with Pandas
- Used by Parquet, Spark, etc.

Why Arrow?
- DataFrame operations on Arrow are 10-100x faster
- Memory efficient
- Standard across languages (Python, R, Java, etc.)
""")

import pyarrow as pa

# Convert DataFrame to Arrow Table
arrow_table = pa.Table.from_pandas(df)
print(f"\n✅ Converted to Arrow Table")
print(f"   Schema: {arrow_table.schema.names[:5]}...")  # First 5 columns

# Convert back to Pandas (zero-copy when possible!)
df_from_arrow = arrow_table.to_pandas()
print(f"✅ Converted back to Pandas: {len(df_from_arrow)} rows")

# -----------------------------
# 3. LAZY LOADING (Chunked Reading)
# -----------------------------
print("\n" + "-" * 40)
print("3. LAZY LOADING (Chunked Reading)")
print("-" * 40)
print("""
What is Lazy Loading / Chunked Reading?
- Don't load entire file into memory
- Process data in small chunks
- Perfect for files larger than RAM!

Example: If you have a 10GB file:
- Normal: Load 10GB into RAM → CRASH!
- Chunked: Load 100MB at a time → Process → Load next chunk
""")

# Simulate chunked reading from database
print("\nChunk processing example:")
chunk_size = 20
total_length = 0
num_chunks = 0

# Process in chunks
conn = sqlite3.connect('netguard.db')
for chunk in pd.read_sql("SELECT * FROM traffic LIMIT 100", conn, chunksize=chunk_size):
    chunk_sum = chunk['length'].sum()
    total_length += chunk_sum
    num_chunks += 1
    print(f"  Chunk {num_chunks}: {len(chunk)} rows, sum={chunk_sum}")

conn.close()
print(f"\n✅ Processed {num_chunks} chunks, total length sum: {total_length}")

# -----------------------------
# 4. MEMORY-MAPPED FILES
# -----------------------------
print("\n" + "-" * 40)
print("4. CSV with Memory Mapping")
print("-" * 40)
print("""
Memory mapping (memory_map=True):
- Maps file directly to virtual memory
- OS handles loading/unloading automatically
- Faster for files that fit in RAM
""")

# Save as CSV first
csv_file = "traffic_sample.csv"
df.to_csv(csv_file, index=False)

# Read with memory mapping (faster for large files)
df_mmap = pd.read_csv(csv_file, memory_map=True)
print(f"✅ Read CSV with memory_map: {len(df_mmap)} rows")

# Clean up example files
import os
os.remove(parquet_file)
os.remove(csv_file)
print(f"✅ Cleaned up example files")

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 60)
print("📚 SUMMARY")
print("=" * 60)

print("""
PHASE 5.2 - Reshaping:
✅ pivot_table() - Long to Wide (like Excel pivot)
✅ melt()        - Wide to Long (unpivot)
✅ stack()       - Columns to Rows
✅ unstack()     - Rows to Columns
✅ MultiIndex    - Hierarchical rows/columns

PHASE 6.3 - Large Datasets:
✅ Parquet       - Fast, compressed, columnar storage
✅ Arrow         - In-memory columnar, zero-copy
✅ Chunked Read  - Process big files in pieces
✅ Memory Map    - Let OS manage file loading

Interview Tips:
- "I use Parquet for storing large datasets - 90% compression, columnar reads"
- "For files bigger than RAM, I use chunked reading with generators"
- "Arrow provides zero-copy data sharing between systems"
""")

print("\n✅ All advanced Pandas techniques completed!")
