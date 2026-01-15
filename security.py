"""
security.py - Attack Pattern Detection Module
Detects SQL Injection, XSS, and other common attack patterns in network traffic.
"""
import re
# Common SQL Injection patterns (simplified for learning)
SQL_INJECTION_PATTERNS = [
    r"('\s*OR\s*'1'\s*=\s*'1)",              # ' OR '1'='1
    r"(;\s*DROP\s+TABLE)",                   # ; DROP TABLE
    r"(UNION\s+SELECT)",                     # UNION SELECT
    r"(--\s*$)",                              # SQL comment at end
    r"('\s*;\s*--)",                          # '; --
    r"(EXEC\s*\()",                           # EXEC()
    r"(xp_cmdshell)",                         # xp_cmdshell (SQL Server)
]
# Common XSS (Cross-Site Scripting) patterns
XSS_PATTERNS = [
    r"(<script.*?>)",                         # <script> tags
    r"(javascript:)",                         # javascript: URLs
    r"(onerror\s*=)",                         # onerror handlers
    r"(onload\s*=)",                          # onload handlers
]
def detect_sql_injection(text):
    """
    Scans text for SQL injection patterns.
    Returns list of matched patterns.
    """
    if not text:
        return []
    
    matches = []
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, str(text), re.IGNORECASE):
            matches.append(pattern)
    return matches
def detect_xss(text):
    """
    Scans text for XSS attack patterns.
    Returns list of matched patterns.
    """
    if not text:
        return []
    
    matches = []
    for pattern in XSS_PATTERNS:
        if re.search(pattern, str(text), re.IGNORECASE):
            matches.append(pattern)
    return matches
def scan_dataframe(df):
    """
    Scans entire DataFrame for attack patterns.
    Returns DataFrame with new 'threat_type' column.
    """
    df = df.copy()
    df['threat_type'] = 'Normal'
    
    # Scan all text columns
    text_cols = ['src_ip', 'dst_ip', 'protocol']
    
    for idx, row in df.iterrows():
        for col in text_cols:
            if col in df.columns:
                val = str(row.get(col, ''))
                
                if detect_sql_injection(val):
                    df.at[idx, 'threat_type'] = '🚨 SQL Injection'
                elif detect_xss(val):
                    df.at[idx, 'threat_type'] = '⚠️ XSS'
    
    return df