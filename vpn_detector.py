"""
vpn_detector.py - VPN Detection Module for NetGuardAI
Detects potential VPN usage based on traffic patterns.
"""
import pandas as pd

# Common VPN ports
VPN_PORTS = {
    1194: "OpenVPN",
    443: "HTTPS/Stealth VPN",
    51820: "WireGuard",
    500: "IPSec IKE",
    4500: "IPSec NAT-T",
    1723: "PPTP",
    1701: "L2TP",
}

# Known VPN provider IP ranges (sample - in production, use a full database)
KNOWN_VPN_PROVIDERS = [
    "185.65.134.",   # NordVPN
    "103.86.96.",    # ExpressVPN
    "198.54.128.",   # Private Internet Access
    "91.108.",       # Various VPNs
    "45.76.",        # Vultr (often used for VPN)
    "104.238.",      # DigitalOcean (VPN servers)
]


def detect_vpn(df):
    """
    Analyzes traffic DataFrame to detect potential VPN usage.
    
    Returns dict with:
        - vpn_detected: bool
        - confidence: str (Low/Medium/High)
        - reason: str (explanation)
        - vpn_server_ip: str or None
        - vpn_type: str or None
    """
    result = {
        'vpn_detected': False,
        'confidence': 'None',
        'reason': 'No VPN indicators found',
        'vpn_server_ip': None,
        'vpn_type': None,
        'indicators': []
    }
    
    if df.empty or len(df) < 10:
        result['reason'] = 'Not enough traffic data to analyze'
        return result
    
    indicators = []
    
    # Check 1: Traffic concentration to single destination
    dst_counts = df['dst_ip'].value_counts()
    total_packets = len(df)
    
    if len(dst_counts) > 0:
        top_dst = dst_counts.index[0]
        top_dst_ratio = dst_counts.iloc[0] / total_packets
        
        if top_dst_ratio > 0.7:  # 70%+ traffic to one IP
            indicators.append(f"High traffic concentration: {top_dst_ratio:.0%} to {top_dst}")
            result['vpn_server_ip'] = top_dst
    
    # Check 2: Known VPN ports
    if 'dst_port' in df.columns:
        for port, vpn_name in VPN_PORTS.items():
            if port in df['dst_port'].values:
                indicators.append(f"VPN port detected: {port} ({vpn_name})")
                result['vpn_type'] = vpn_name
    
    # Check 3: Known VPN provider IPs
    for ip_prefix in KNOWN_VPN_PROVIDERS:
        matching_ips = df[df['dst_ip'].str.startswith(ip_prefix, na=False)]
        if len(matching_ips) > 0:
            indicators.append(f"Known VPN provider IP range: {ip_prefix}*")
            result['vpn_server_ip'] = matching_ips['dst_ip'].iloc[0]
    
    # Determine confidence based on indicators
    if len(indicators) >= 3:
        result['vpn_detected'] = True
        result['confidence'] = 'High'
        result['reason'] = 'Multiple VPN indicators detected'
    elif len(indicators) == 2:
        result['vpn_detected'] = True
        result['confidence'] = 'Medium'
        result['reason'] = 'Some VPN indicators present'
    elif len(indicators) == 1:
        result['vpn_detected'] = True
        result['confidence'] = 'Low'
        result['reason'] = 'Possible VPN usage'
    
    result['indicators'] = indicators
    
    return result


def get_traffic_diversity_score(df):
    """
    Calculate how diverse the traffic destinations are.
    Lower score = more concentrated (VPN-like)
    Higher score = more diverse (normal browsing)
    """
    if df.empty:
        return 0
    
    unique_dsts = df['dst_ip'].nunique()
    total_packets = len(df)
    
    # Normalize: more unique destinations per packet = higher diversity
    diversity = (unique_dsts / total_packets) * 100
    return min(diversity, 100)  # Cap at 100


# Test
if __name__ == "__main__":
    # Sample test data
    test_df = pd.DataFrame({
        'dst_ip': ['185.65.134.50'] * 80 + ['8.8.8.8'] * 20,
        'dst_port': [1194] * 50 + [443] * 50
    })
    
    result = detect_vpn(test_df)
    print("VPN Detection Result:")
    for k, v in result.items():
        print(f"  {k}: {v}")
