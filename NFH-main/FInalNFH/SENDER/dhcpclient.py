import socket
import struct
import random

# DHCP message types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5

# Generate a random MAC address
def generate_mac():
    return [0x00, 0x16, 0x3e, random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff), random.randint(0x00, 0xff)]

# Create a DHCP Discover packet
def create_discover(xid, mac_addr):
    packet = bytearray(1024)
    packet[0] = 1  # Boot request
    packet[1] = 1  # Ethernet
    packet[2] = 6  # MAC address length
    packet[3] = 0  # Hops
    struct.pack_into('!I', packet, 4, xid)  # Transaction ID
    struct.pack_into('!H', packet, 28, 0x8000)  # Flags (broadcast)
    packet[0x2c:0x32] = mac_addr  # Client MAC address

    # DHCP options
    packet[0x32] = 53  # DHCP message type
    packet[0x33] = 1   # Length
    packet[0x34] = DHCP_DISCOVER  # Message type: DHCP Discover
    packet[0x35] = 255  # End of options

    return bytes(packet[:0x36])

# Main function
def main():
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Generate a random MAC address
    mac_addr = bytes(generate_mac())

    # Create a DHCP Discover packet
    xid = random.randint(0, 0xFFFFFFFF)
    discover_packet = create_discover(xid, mac_addr)
    print("Sending DHCP Discover...")
    while True:
        sock.sendto(discover_packet, ('127.0.0.1', 67))  # Replace '<DHCP_SERVER_IP>' with the actual IP address of the DHCP server

    # Wait for DHCP Offer or Acknowledgement
    while True:
        data, addr = sock.recvfrom(1024)
        if data[0] == DHCP_OFFER:
            print("Received DHCP Offer from server")
            break

    # Close socket
    sock.close()

if __name__ == "__main__":
    main()
