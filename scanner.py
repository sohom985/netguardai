from scapy.all import sr1, IP, TCP
# The target we want to scan (Google's Public DNS is safe to scan)
TARGET_IP = "8.8.8.8" 
# We will scan these common ports
PORTS_TO_SCAN = [21, 22, 53, 80, 443]
def scan_port(port):
    print(f"Scanning port {port}...", end=" ")
    
    # 1. Create a SYN packet
    # flags="S" means SYN (Synchronize)
    packet = IP(dst=TARGET_IP) / TCP(dport=port, flags="S")
    
    # 2. Send it and wait for a reply (timeout after 1 second)
    # sr1 = Send and Receive 1 packet
    response = sr1(packet, timeout=1, verbose=0)
    
    # 3. Analyze the response
    if response is None:
        print("Filtered (No response)")
    elif response.haslayer(TCP):
        # Check the flags in the response
        # 0x12 is the hex code for SYN+ACK (Open)
        # 0x14 is the hex code for RST (Closed)
        if response[TCP].flags == 0x12:
            print("OPEN! ✅")
            # Be polite: Send a RST to close the connection
            rst_pkt = IP(dst=TARGET_IP) / TCP(dport=port, flags="R")
            sr1(rst_pkt, timeout=1, verbose=0)
        elif response[TCP].flags == 0x14:
            print("Closed ❌")
    else:
        print("Unknown response")
def start_scan():
    print(f"Starting Stealth SYN Scan on {TARGET_IP}...")
    for port in PORTS_TO_SCAN:
        scan_port(port)
if __name__ == "__main__":
    start_scan()