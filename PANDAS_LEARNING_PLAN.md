# 🐼 Pandas Mastery Curriculum

## NetGuardAI Learning Project

**Student:** Priyanka Dey  
**Start Date:** December 4, 2025  
**Goal:** R&D-level Pandas expertise through network security project

---

## PHASE 1: Core Foundations

**Duration:** 1-2 weeks  
**Status:** [ ] Not Started

## Lesson 1.1: Data Structures

**Concepts:** Series, DataFrame, Index

### What You'll Learn

- A **Series** is like a single column (1D array with labels)
- A **DataFrame** is like an Excel spreadsheet (2D table with rows & columns)
- An **Index** is the row labels (like row numbers, but can be anything)

### Your Task

Open `analyzer.py` and do the following:

```python
# Step 1: Load your traffic data
import pandas as pd
import sqlite3

conn = sqlite3.connect("netguard.db")
df = pd.read_sql("SELECT * FROM traffic", conn)
conn.close()

# Step 2: Explore the DataFrame
print(df)                    # See the whole table
print(df.shape)              # (rows, columns)
print(df.columns)            # Column names
print(df.dtypes)             # Data types of each column
print(df.info())             # Summary info

# Step 3: Access a Series (single column)
print(df['src_ip'])          # This is a Series!
print(type(df['src_ip']))    # Confirm it's a Series

# Step 4: Check the Index
print(df.index)              # Row labels (0, 1, 2, ...)
```

### Checkpoint Questions

- [ ] How many rows does your DataFrame have?
- [ ] What are the column names?
- [ ] What data type is the 'length' column?

---

## Lesson 1.2: Selection & Filtering

**Concepts:** .loc, .iloc, Boolean masking, .query()

### Selection Concepts

- `.iloc` = Select by **position** (integer location)
- `.loc` = Select by **label** (index label)
- Boolean masking = Filter rows based on conditions
- `.query()` = SQL-like filtering syntax

### Practice: Selection & Filtering

```python
# .iloc - Select by POSITION (like array indexing)
print(df.iloc[0])            # First row
print(df.iloc[0:5])          # First 5 rows
print(df.iloc[0, 2])         # First row, third column

# .loc - Select by LABEL
print(df.loc[0])             # Row with index label 0
print(df.loc[0:5, 'src_ip']) # Rows 0-5, only 'src_ip' column

# Boolean Masking - Filter with conditions
tcp_only = df[df['protocol'] == 'TCP']
print(tcp_only)

# Multiple conditions (use & for AND, | for OR)
big_tcp = df[(df['protocol'] == 'TCP') & (df['length'] > 100)]
print(big_tcp)

# .query() - Cleaner syntax
result = df.query("protocol == 'TCP' and length > 100")
print(result)
```

### Checkpoint: Selection & Filtering

- [ ] How many TCP packets are there?
- [ ] What's the largest packet? (use `df['length'].max()`)
- [ ] Can you filter packets from a specific IP?

---

## Lesson 1.3: Essential Operations

**Concepts:** Sorting, renaming, astype, duplicates, missing data

### Practice: Essential Operations

```python
# Sorting
df_sorted = df.sort_values('length', ascending=False)  # Biggest first
print(df_sorted.head())

# Sort by multiple columns
df_sorted = df.sort_values(['protocol', 'length'], ascending=[True, False])

# Renaming columns
df_renamed = df.rename(columns={'src_ip': 'source_ip', 'dst_ip': 'destination_ip'})
print(df_renamed.columns)

# Type casting with astype()
print(df['length'].dtype)                    # Check current type
df['length'] = df['length'].astype('int32')  # Convert to smaller int

# Check for duplicates
print(df.duplicated().sum())                 # Count duplicates
df_clean = df.drop_duplicates()              # Remove duplicates

# Missing data
print(df.isnull().sum())                     # Count missing per column
df_filled = df.fillna(0)                     # Fill missing with 0
df_dropped = df.dropna()                     # Remove rows with missing
```

### Checkpoint: Essential Operations

- [ ] What's the 5 largest packets by length?
- [ ] Are there any duplicate rows?
- [ ] Are there any missing values?

---

## Lesson 1.4: Categorical Data

**Concepts:** Converting to Categorical type (saves memory!)

### Practice: Categorical Data

```python
# Check memory BEFORE
print(df.memory_usage(deep=True))

# Convert protocol to categorical
df['protocol'] = df['protocol'].astype('category')

# Check memory AFTER
print(df.memory_usage(deep=True))  # Should be smaller!

# See the categories
print(df['protocol'].cat.categories)  # ['TCP', 'UDP', 'Other']
```

---

## Lesson 1.5: Custom Functions

**Concepts:** apply, map, vectorization

### Practice: Custom Functions

```python
# map() - Apply to a Series (like a dictionary lookup)
protocol_scores = {'TCP': 1, 'UDP': 2, 'Other': 0}
df['protocol_score'] = df['protocol'].map(protocol_scores)

# apply() - Apply a function to each row/column
def classify_size(length):
    if length < 100:
        return 'small'
    elif length < 500:
        return 'medium'
    else:
        return 'large'

df['size_category'] = df['length'].apply(classify_size)
print(df[['length', 'size_category']].head(10))

# Vectorization (FASTER than apply!)
# Instead of apply, use numpy-style operations
df['is_big'] = df['length'] > 500  # Boolean column, very fast!
```

### ⚠️ Important Rule

**AVOID apply() when possible!** Vectorized operations are 100x faster.

---

## PHASE 2: Advanced Manipulation

**Duration:** 1-2 weeks  
**Status:** [ ] Not Started

## Lesson 2.1: GroupBy Mastery

**Concepts:** groupby, agg, transform, filter

### Practice: GroupBy Operations

```python
# Basic GroupBy
grouped = df.groupby('protocol')
print(grouped['length'].mean())  # Average length per protocol

# Multiple aggregations with .agg()
stats = df.groupby('protocol').agg({
    'length': ['count', 'mean', 'max', 'min'],
    'id': 'count'
})
print(stats)

# Named aggregations (cleaner)
stats = df.groupby('protocol').agg(
    packet_count=('id', 'count'),
    avg_length=('length', 'mean'),
    max_length=('length', 'max')
)
print(stats)

# transform() - Add group stats back to every row
df['avg_length_for_protocol'] = df.groupby('protocol')['length'].transform('mean')
print(df[['protocol', 'length', 'avg_length_for_protocol']].head(10))

# filter() - Keep only groups meeting a condition
# Keep only protocols with more than 5 packets
df_filtered = df.groupby('protocol').filter(lambda x: len(x) > 5)
```

---

## Lesson 2.2: Merging & Joining

**Concepts:** merge, join, concat

### Practice: Merging & Joining

First, create a second DataFrame (threat intelligence):

```python
# Create a "threat database"
threat_data = pd.DataFrame({
    'ip': ['1.2.3.4', '192.168.1.1', '10.0.0.1'],
    'threat_level': ['HIGH', 'LOW', 'MEDIUM'],
    'country': ['Unknown', 'Local', 'Local']
})

# Merge traffic with threat data
merged = pd.merge(
    df, 
    threat_data, 
    left_on='src_ip',     # Column from df
    right_on='ip',        # Column from threat_data
    how='left'            # Keep all rows from df
)
print(merged[['src_ip', 'threat_level', 'country']].head())

# Concatenate (stack DataFrames)
# Useful for combining multiple capture sessions
session1 = df.head(10)
session2 = df.tail(10)
combined = pd.concat([session1, session2], ignore_index=True)
```

---

## Lesson 2.3: MultiIndex

**Concepts:** Hierarchical indexing

### Practice: MultiIndex

```python
# Create MultiIndex
df_multi = df.set_index(['protocol', 'src_ip'])
print(df_multi)

# Access data with MultiIndex
print(df_multi.loc['TCP'])           # All TCP packets
print(df_multi.loc[('TCP', '192.168.1.1')])  # Specific

# Cross-section with .xs()
print(df_multi.xs('TCP', level='protocol'))

# Reset index back to columns
df_reset = df_multi.reset_index()
```

---

## Lesson 2.4: Pivot & Melt (Reshaping Data)

**Concepts:** pivot, pivot_table, melt (wide to long conversion)

### Reshaping Concepts

- **Wide format** = Many columns, few rows (like a spreadsheet)
- **Long format** = Few columns, many rows (like a database)
- `pivot()` = Long to Wide
- `melt()` = Wide to Long
- `pivot_table()` = Like Excel pivot tables!

### Practice: Pivot & Melt

```python
# Create sample data (packets per hour by protocol)
wide_data = pd.DataFrame({
    'hour': [0, 1, 2, 3],
    'TCP': [100, 150, 80, 200],
    'UDP': [50, 30, 40, 60],
    'Other': [10, 5, 8, 12]
})
print("WIDE format:")
print(wide_data)

# MELT: Wide to Long (unpivot)
long_data = pd.melt(
    wide_data,
    id_vars=['hour'],
    value_vars=['TCP', 'UDP', 'Other'],
    var_name='protocol',
    value_name='packet_count'
)
print("LONG format:")
print(long_data)

# PIVOT: Long to Wide
back_to_wide = long_data.pivot(
    index='hour',
    columns='protocol',
    values='packet_count'
)
print("Back to WIDE:")
print(back_to_wide)

# PIVOT_TABLE: Like Excel, with aggregation!
pivot = df.pivot_table(
    values='length',
    index='src_ip',
    columns='protocol',
    aggfunc='mean',
    fill_value=0
)
print("Pivot Table (avg packet length by IP and protocol):")
print(pivot)
```

### Checkpoint: Pivot & Melt

- [ ] What is the difference between pivot() and pivot_table()?
- [ ] When would you use melt?
- [ ] Can you create a pivot table showing packet COUNT by IP and protocol?

---

## PHASE 3: Data Cleaning

**Duration:** 1 week  
**Status:** [ ] Not Started

## Lesson 3.1: String Operations

**Concepts:** .str API

### Practice: String Operations

```python
# String operations on IP addresses
df['ip_parts'] = df['src_ip'].str.split('.')  # Split by dot
df['first_octet'] = df['src_ip'].str.split('.').str[0]  # Get first part

# Check if IP starts with "192"
df['is_local'] = df['src_ip'].str.startswith('192')

# Use regex
df['is_valid_ip'] = df['src_ip'].str.match(r'^\d+\.\d+\.\d+\.\d+$')
```

---

## Lesson 3.2: Datetime Operations

**Concepts:** Parsing, resampling

### Practice: Datetime Operations

```python
# Convert timestamp to datetime (if not already)
df['timestamp'] = pd.to_datetime(df['timestamp'])

# Set as index for time-series operations
df.set_index('timestamp', inplace=True)

# Resample - aggregate by time period
packets_per_minute = df.resample('1T').size()  # 1T = 1 minute
packets_per_hour = df.resample('1H').size()

# Extract date parts
df['hour'] = df.index.hour
df['day_of_week'] = df.index.dayofweek
df['date'] = df.index.date
```

---

## PHASE 4: Performance

**Duration:** 1 week  
**Status:** [ ] Not Started

## Lesson 4.1: Memory Optimization

### Practice: Memory Optimization

```python
# Check current memory
print(df.memory_usage(deep=True))

# Downcast integers
df['length'] = pd.to_numeric(df['length'], downcast='integer')

# Convert strings to categoricals
for col in ['protocol', 'src_ip', 'dst_ip']:
    if df[col].dtype == 'object':
        df[col] = df[col].astype('category')

# Check memory AFTER
print(df.memory_usage(deep=True))
```

---

## Lesson 4.2: Chunked Reading (for big files)

### Practice: Chunked Reading

```python
# Read CSV in chunks (for files too big for memory)
chunk_size = 10000
results = []

for chunk in pd.read_csv('huge_file.csv', chunksize=chunk_size):
    # Process each chunk
    chunk_result = chunk.groupby('protocol')['length'].mean()
    results.append(chunk_result)

# Combine results
final = pd.concat(results).groupby(level=0).mean()
```

---

## PHASE 5: Time Series

**Duration:** 1 week  
**Status:** [ ] Not Started

## Lesson 5.1: Rolling & Expanding Windows

### Practice: Rolling & Expanding Windows

```python
# Set timestamp as index
df.set_index('timestamp', inplace=True)
df = df.sort_index()

# Rolling average (last 5 packets)
df['rolling_avg_length'] = df['length'].rolling(window=5).mean()

# Expanding (cumulative)
df['cumulative_packets'] = df['length'].expanding().count()

# Rolling with time window
df['5min_avg'] = df['length'].rolling('5T').mean()  # 5 minute window
```

---

## PHASE 6: Feature Engineering for ML

**Duration:** 1 week  
**Status:** [ ] Not Started

## Lesson 6.1: Lag Features

### Practice: Lag Features

```python
# Create lag features (previous values)
df['prev_length'] = df['length'].shift(1)      # 1 packet ago
df['prev_length_2'] = df['length'].shift(2)    # 2 packets ago

# Difference from previous
df['length_diff'] = df['length'].diff()

# Percentage change
df['length_pct_change'] = df['length'].pct_change()
```

---

## PHASE 7: Visualization

**Duration:** 3-4 days  
**Status:** [ ] Not Started

## Lesson 7.1: Pandas Built-in Plotting

### Practice: Pandas Plotting

```python
import matplotlib.pyplot as plt

# Quick histogram
df['length'].plot(kind='hist', bins=30, title='Packet Length Distribution')
plt.savefig('length_histogram.png')

# Protocol counts
df['protocol'].value_counts().plot(kind='bar', title='Packets by Protocol')
plt.savefig('protocol_bar.png')

# Time series
df.resample('1T').size().plot(title='Packets per Minute')
plt.savefig('packets_timeline.png')
```

---

## PHASE 8: Real-World R&D Skills

**Duration:** 1 week  
**Status:** [ ] Not Started

## Lesson 8.1: Parquet & Arrow (Fast File Formats)

**Concepts:** Parquet, Feather, PyArrow backend

### What You'll Learn (8.1)

- **CSV** is slow and big
- **Parquet** is fast and small (columnar storage)
- **Feather** is super fast for temporary files

### Your Task (8.1)

```python
# Save to Parquet (much faster than CSV!)
df.to_parquet('traffic.parquet')

# Read from Parquet
df_parquet = pd.read_parquet('traffic.parquet')

# Save to Feather (even faster for temp files)
df.to_feather('traffic.feather')

# Compare file sizes
import os
print(f"Parquet size: {os.path.getsize('traffic.parquet')} bytes")
```

---

## Lesson 8.2: Handling Messy Real-World Data

**Concepts:** Mixed formats, duplicate timestamps, irregular frequencies

### What You'll Learn (8.2)

Real data is MESSY! You need to handle:

- Duplicate timestamps
- Irregular time gaps
- Mixed data types

### Your Task (8.2)

```python
# Check for duplicate timestamps
print(f"Duplicate timestamps: {df['timestamp'].duplicated().sum()}")

# Keep last occurrence of duplicates
df_clean = df.drop_duplicates(subset='timestamp', keep='last')

# Find time gaps
df['time_gap'] = df['timestamp'].diff()

# Find large gaps (> 10 seconds)
large_gaps = df[df['time_gap'] > pd.Timedelta(seconds=10)]
print(f"Found {len(large_gaps)} large time gaps")

# Handle mixed types
df['length'] = pd.to_numeric(df['length'], errors='coerce')
```

---

## Lesson 8.3: Out-of-Core Computation (Huge Datasets)

**Concepts:** Dask, lazy loading

### What You'll Learn (8.3)

When data is TOO BIG for memory, use lazy computation with Dask.

### Your Task (8.3)

```python
# Option 1: Chunk processing (pure Pandas)
def process_large_file(filepath, chunksize=10000):
    results = []
    for chunk in pd.read_csv(filepath, chunksize=chunksize):
        chunk_stats = chunk.groupby('protocol')['length'].mean()
        results.append(chunk_stats)
    return pd.concat(results).groupby(level=0).mean()

# Option 2: Using Dask (pip install dask)
import dask.dataframe as dd

df_dask = dd.read_csv('huge_file.csv')
result = df_dask.groupby('protocol')['length'].mean()
print(result.compute())  # .compute() runs it
```

---

## PHASE 9: Scientific Computation & Statistics

**Duration:** 3-4 days  
**Status:** [ ] Not Started

## Lesson 9.1: Descriptive Statistics Deep Dive

**Concepts:** Percentiles, weighted stats, correlations

### Your Task (9.1)

```python
# Basic descriptive stats
print(df['length'].describe())

# Specific percentiles
print(df['length'].quantile([0.1, 0.5, 0.9, 0.95, 0.99]))

# Correlation
print(df[['length', 'protocol_num']].corr())

# Mode (most common value)
print(f"Most common protocol: {df['protocol'].mode()[0]}")

# Skewness and Kurtosis
print(f"Skewness: {df['length'].skew()}")
print(f"Kurtosis: {df['length'].kurtosis()}")
```

---

## Lesson 9.2: Bootstrapping with Pandas

**Concepts:** Resampling for confidence intervals

### What You'll Learn (9.2)

**Bootstrapping** = Resample your data many times to estimate uncertainty.

### Your Task (9.2)

```python
import numpy as np

def bootstrap_mean(data, n_iterations=1000):
    means = []
    n = len(data)
    
    for _ in range(n_iterations):
        sample = data.sample(n=n, replace=True)
        means.append(sample.mean())
    
    means = pd.Series(means)
    return {
        'mean': means.mean(),
        'lower_95': means.quantile(0.025),
        'upper_95': means.quantile(0.975)
    }

result = bootstrap_mean(df['length'])
print(f"Mean: {result['mean']:.2f}")
print(f"95% CI: [{result['lower_95']:.2f}, {result['upper_95']:.2f}]")
```

### Checkpoint Questions (9.2)

- [ ] What does bootstrapping tell you that .mean() does not?
- [ ] Why do we sample with replacement?

---

## PHASE 10: Capstone Project 🚀

**Duration:** 1 week  
**Status:** [ ] Not Started

> [!IMPORTANT]
> This is your FINAL PROJECT! You'll combine everything you learned to build something real.

## Project: NetGuardAI Chatbot

Build a **natural language chatbot** that lets anyone analyze your network traffic data just by asking questions in plain English!

### What You'll Build

| Feature | Description |
|---------|-------------|
| 🤖 AI Backend | Gemini API (free) + Local Llama fallback |
| 💬 Chat Interface | Web-based chat (Streamlit) |
| 📊 Visualizations | Interactive Plotly charts |
| 📥 Exports | Download to Excel/CSV |

### Example Conversations

```text
User: "How many packets are in the database?"
Bot:  "There are 1,247 packets captured."

User: "Show me the top 5 source IPs"
Bot:  [Displays table + bar chart]

User: "Export all TCP traffic to Excel"
Bot:  [Download button appears]
```

### Prerequisites (All FREE!)

Before starting this phase:

1. **Get Gemini API Key** (2 minutes, no credit card)
   - Go to <https://aistudio.google.com/app/apikey>
   - Click "Create API Key"

2. **Install Ollama** (local AI, completely free)
   - Download from <https://ollama.com>
   - Run: `ollama pull llama3.2`

### Lesson 10.1: Project Setup

```python
# Create project structure
# You'll create these files:
# - app.py (Streamlit web app)
# - chatbot/llm_client.py (AI integration)
# - chatbot/data_engine.py (Pandas query executor)
# - chatbot/chart_generator.py (Plotly charts)
# - chatbot/file_exporter.py (Excel/CSV export)
```

### Lesson 10.2: LLM Integration

You'll learn:

- How to call the Gemini API
- How to use Ollama for local AI
- Prompt engineering for data analysis
- Automatic failover between models

### Lesson 10.3: Building the Data Engine

You'll apply your Pandas skills:

- Query execution from natural language
- DataFrame manipulation
- Aggregations and groupby
- Time series operations

### Lesson 10.4: Visualization & Export

You'll create:

- Interactive Plotly charts
- Auto-detection of best chart type
- Excel and CSV export functions

### Lesson 10.5: Web Interface

You'll build:

- Chat interface with Streamlit
- Message history
- File download buttons
- Model toggle switch

### Checkpoint Questions (10)

- [ ] Can your chatbot answer "How many TCP packets are there?"
- [ ] Does it show a chart for "Show protocol distribution"?
- [ ] Can users download data as Excel?
- [ ] Does it fall back to Llama when Gemini fails?

---

## 📋 PROGRESS TRACKER

| Phase | Topic | Status | Date Started | Date Completed |
|-------|-------|--------|--------------|----------------|
| 1.1 | Data Structures | [ ] | | |
| 1.2 | Selection & Filtering | [ ] | | |
| 1.3 | Essential Operations | [ ] | | |
| 1.4 | Categorical Data | [ ] | | |
| 1.5 | Custom Functions | [ ] | | |
| 2.1 | GroupBy | [ ] | | |
| 2.2 | Merging & Joining | [ ] | | |
| 2.3 | MultiIndex | [ ] | | |
| 2.4 | Pivot & Melt | [ ] | | |
| 3.1 | String Operations | [ ] | | |
| 3.2 | Datetime Operations | [ ] | | |
| 4.1 | Memory Optimization | [ ] | | |
| 4.2 | Chunked Reading | [ ] | | |
| 5.1 | Rolling Windows | [ ] | | |
| 6.1 | Feature Engineering | [ ] | | |
| 7.1 | Visualization | [ ] | | |
| 8.1 | Parquet & Arrow | [ ] | | |
| 8.2 | Messy Data Handling | [ ] | | |
| 8.3 | Out-of-Core (Dask) | [ ] | | |
| 9.1 | Descriptive Statistics | [ ] | | |
| 9.2 | Bootstrapping | [ ] | | |
| 10.1 | Chatbot: Project Setup | [ ] | | |
| 10.2 | Chatbot: LLM Integration | [ ] | | |
| 10.3 | Chatbot: Data Engine | [ ] | | |
| 10.4 | Chatbot: Visualization & Export | [ ] | | |
| 10.5 | Chatbot: Web Interface | [ ] | | |

---

## 🎯 HOW TO USE THIS DOCUMENT

1. **Start with Phase 1, Lesson 1.1**
2. **Read the explanation** (What You'll Learn)
3. **Type the code yourself** (don't copy-paste!)
4. **Answer the Checkpoint Questions**
5. **Ask your teacher (me!) if stuck**
6. **Mark complete in Progress Tracker**
7. **Move to next lesson**

---

**Remember:** You're not dumb! Pandas is just new. Take it slow. 🐢
