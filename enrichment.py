import pandas as pd
import requests
import ipaddress
import time

def is_local_ip(ip):
    """Checks if an IP address is local/private."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        return False  # Not a valid IP (e.g., 'localhost')

def get_ip_info(ip):
    """
    Fetches Geolocation and ISP info for a public IP using ip-api.com.
    Returns a dictionary with default values if failed or local.
    """
    # 1. Check if Local (Don't query API for local IPs)
    if is_local_ip(ip):
        return {
            'ip': ip,
            'country': 'Local Network',
            'city': 'Local',
            'isp': 'Local Device',
            'lat': None,
            'lon': None,
            'threat_level': 'Safe'
        }

    # 2. Query API for Public IPs
    try:
        # Rate limit: ip-api allows 45 requests/minute. Sleep slightly to be safe.
        time.sleep(1.5) 
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        
        if data['status'] == 'success':
            return {
                'ip': ip,
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'lat': data.get('lat'),
                'lon': data.get('lon'),
                'threat_level': 'Public (Check AbuseIPDB)'  # Placeholder for real check
            }
    except Exception as e:
        print(f"API Error for {ip}: {e}")
    
    return {
        'ip': ip,
        'country': 'Unknown',
        'city': 'Unknown',
        'isp': 'Unknown',
        'lat': None,
        'lon': None,
        'threat_level': 'Unknown'
    }

def merge_threat_intel(df):
    """
    Enriches traffic data with Geolocation and Threat info.
    Fetches real data for unique IPs and merges it back.
    """
    if 'dst_ip' not in df.columns:
        return df

    print("--- Fetching GeoIP Data (This might take a moment...) ---")
    
    # 1. Get unique Destination IPs
    unique_ips = df['dst_ip'].unique()
    
    # 2. Fetch info for each IP
    ip_data = []
    for ip in unique_ips:
        print(f"Enriching: {ip}...")
        info = get_ip_info(ip)
        ip_data.append(info)
    
    # 3. Create DataFrame
    threat_df = pd.DataFrame(ip_data)
    
    # 4. Merge back to main DataFrame
    merged = pd.merge(
        df,
        threat_df,
        left_on='dst_ip',
        right_on='ip',
        how='left'
    )
    
    # Drop duplicate 'ip' column from merge if it exists
    if 'ip' in merged.columns and 'ip' != 'dst_ip':
        merged = merged.drop(columns=['ip'])
        
    return merged
