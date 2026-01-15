"""
packet_forger.py - Create and send custom network packets using Scapy
Requires sudo to run: sudo python packet_forger.py
"""
from scapy.all import send, IP, ICMP, TCP, UDP

def send_fake_ping():
    """Sends a fake ICMP ping packet."""
    # Create the IP Layer (spoofed source)
    ip_layer = IP(src="1.2.3.4", dst="127.0.0.1")
    
    # Create the ICMP Layer (Ping)
    icmp_layer = ICMP()
    
    # Stack them together
    packet = ip_layer / icmp_layer
    
    print("Sending fake ICMP ping...")
    packet.show()
    send(packet)
    print("✅ Packet sent!")

def send_fake_tcp():
    """Sends a fake TCP SYN packet."""
    ip_layer = IP(src="10.0.0.1", dst="127.0.0.1")
    tcp_layer = TCP(sport=12345, dport=80, flags="S")  # SYN flag
    
    packet = ip_layer / tcp_layer
    
    print("Sending fake TCP SYN...")
    packet.show()
    send(packet)
    print("✅ Packet sent!")

def send_fake_udp():
    """Sends a fake UDP packet."""
    ip_layer = IP(src="172.16.0.1", dst="127.0.0.1")
    udp_layer = UDP(sport=54321, dport=53)  # DNS port
    
    packet = ip_layer / udp_layer / b"Hello from forged packet!"
    
    print("Sending fake UDP packet...")
    packet.show()
    send(packet)
    print("✅ Packet sent!")

if __name__ == "__main__":
    print("🔧 Packet Forger Tool")
    print("(Requires sudo to run)")
    print()
    print("1. Send fake ICMP ping")
    print("2. Send fake TCP SYN")
    print("3. Send fake UDP packet")
    choice = input("Choose (1/2/3): ")
    
    if choice == "1":
        send_fake_ping()
    elif choice == "2":
        send_fake_tcp()
    elif choice == "3":
        send_fake_udp()
    else:
        print("Invalid choice")