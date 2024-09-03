# Devil-deauth
it automatically scan all network connections nearby and send deauthentication packets


Requirements

Python Environment: Python 3.x installed.
Scapy Library: Install it using:

    pip3 install scapy

Wireless Network Interface: Ensure your Wi-Fi adapter supports monitor mode.
Operating System: Linux-based system is preferred.

Setting Up Monitor Mode Manually

Before running the script, you can set your wireless interface to monitor mode manually using the following commands (replace wlan0 with your interface name):

    sudo ip link set wlan0 down
    sudo iw dev wlan0 set type monitor
    sudo ip link set wlan0 up

Explanation of the Script

  Setting Monitor Mode: You need to set your wireless interface to monitor mode manually before running the script.
  
  Packet Creation: The send_deauth function creates a deauthentication packet for the specified BSSID and sends it using scapy.sendp.

  Network Scanning: The scan_networks function captures packets, extracts the BSSID and SSID, and stores them in the scanned_networks list.

  Main Loop: The script continuously scans for networks, prints the scanned connections, and sends deauth packets to each detected BSSID.

Important Notes

  Run as Root: Make sure to run the script with root privileges using sudo.
  
  Legal and Ethical Considerations: Ensure you have permission to perform these actions on the network.
  
  Monitor Mode: Ensure your wireless card supports monitor mode and is set up correctly.
  
  Error Handling: You may want to add error handling for better robustness, especially when dealing with network interfaces.
