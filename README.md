# Capstone_Project
!pip install scapy psutil
!apt-get update
!apt-get install -y libpcap-dev

import psutil
import socket

from scapy.all import sniff, get_if_list

# Step 1: List all network interfaces and their details
def list_network_interfaces():
    # Get network interface addresses
    interfaces = psutil.net_if_addrs()
    interface_stats = psutil.net_if_stats()

    print("Network interfaces and their details:")
    for iface_name, iface_addresses in interfaces.items():
        print(f"\nInterface: {iface_name}")
        # Print interface status (up or down)
        is_up = interface_stats[iface_name].isup
        print(f"Status: {'UP' if is_up else 'DOWN'}")

        # Print all IP and MAC addresses associated with this interface
        for address in iface_addresses:
            if address.family == socket.AF_INET:
                print(f"  IPv4 Address: {address.address}")
                print(f"  Netmask: {address.netmask}")
                print(f"  Broadcast IP: {address.broadcast}")
            elif address.family == socket.AF_INET6:
                print(f"  IPv6 Address: {address.address}")
                print(f"  Netmask: {address.netmask}")
            elif address.family == psutil.AF_LINK:
                print(f"  MAC Address: {address.address}")

# Step 2: Capture incoming network packets on a specified interface
def capture_incoming_packets(interface='wlan0', packet_count=0):
    # Define a callback function to process captured packets
    def packet_callback(packet):
        # Check if the packet is an incoming packet
        if packet.haslayer("IP") and packet["IP"].dst == psutil.net_if_addrs()[interface][0].address:
            print(packet.summary())  # Print a summary of each captured packet

    print(f"\nStarting packet capture on interface: {interface}")
    # Capture incoming packets on the specified network interface
    # Filter for IP packets directed to this interface (incoming traffic)
    sniff(iface=interface, prn=packet_callback, count=packet_count, filter="ip")

# Step 3: Main function to list interfaces and start packet capture
if __name__ == "__main__":
    # List available network interfaces
    list_network_interfaces()

    # Prompt the user to enter the interface they want to use for packet capture
    available_interfaces = get_if_list()
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(available_interfaces, start=1):
        print(f"{i}. {iface}")

    try:
        interface_choice = int(input("\nEnter the number of the interface to capture packets from: "))
        selected_interface = available_interfaces[interface_choice - 1]
    except (ValueError, IndexError):
        print("Invalid selection. Defaulting to 'wlan0'.")
        selected_interface = 'wlan0'

    # Capture packets (0 means capture indefinitely)
    capture_incoming_packets
