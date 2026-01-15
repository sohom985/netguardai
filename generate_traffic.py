#!/usr/bin/env python3
"""
generate_traffic.py - Generate traffic to public IPs for geolocation testing
Makes HTTP requests to websites around the world so the packet sniffer
captures real public IP addresses.
"""
import requests
import time

# Websites from different countries/regions
TARGETS = [
    ("https://www.google.com", "USA"),
    ("https://www.baidu.com", "China"),
    ("https://www.bbc.co.uk", "UK"),
    ("https://www.lemonde.fr", "France"),
    ("https://www.spiegel.de", "Germany"),
    ("https://www.ansa.it", "Italy"),
    ("https://www.asahi.com", "Japan"),
    ("https://www.globo.com", "Brazil"),
    ("https://www.abc.net.au", "Australia"),
    ("https://timesofindia.indiatimes.com", "India"),
]

def generate_traffic():
    print("🌍 Generating traffic to public IPs around the world...")
    print("=" * 50)
    
    for url, country in TARGETS:
        try:
            print(f"📡 Requesting {country}: {url}")
            response = requests.get(url, timeout=10)
            print(f"   ✅ Status: {response.status_code}")
            time.sleep(0.5)  # Small delay between requests
        except Exception as e:
            print(f"   ❌ Failed: {e}")
    
    print("\n" + "=" * 50)
    print("✅ Done! Refresh the dashboard to see geolocations.")
    print("   http://localhost:8501")

if __name__ == "__main__":
    generate_traffic()
