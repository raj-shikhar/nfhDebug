import socket
import struct
import random
import time

# DHCP message types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5

# DHCP option codes
OPTION_SUBNET_MASK = 1
OPTION_ROUTER = 3
OPTION_DNS_SERVER = 6
OPTION_LEASE_TIME = 51
OPTION_DHCP_SERVER_ID = 54
OPTION_END = 255

# DHCP lease time (in seconds)
LEASE_TIME = 3600  # 1 hour

# DHCP server configuration
SERVER_IP = '192.168.1.1'
SUBNET_MASK = '255.255.255.0'
ROUTER = '192.168.1.1'
DNS_SERVER = '8.8.8.8'

# Generate a random MAC address
def generate_mac():
    return [0x00, 0x16, 0x3e, random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff), random.randint(0x00, 0xff)]

# Create a DHCP offer packet
def create_offer(xid, mac_addr):
    packet = bytearray(1024)
    packet[0] = 2  # Boot reply
    packet[1] = 1  # Ethernet
    packet[2] = 6  # MAC address length
    packet[3] = 0  # Hops
    struct.pack_into('!I', packet, 4, xid)  # Transaction ID
    struct.pack_into('!H', packet, 28, 0x8000)  # Flags (broadcast)
    packet[0x2c:0x32] = mac_addr  # Client MAC address

    # DHCP options
    options = [
        (OPTION_SUBNET_MASK, SUBNET_MASK),
        (OPTION_ROUTER, ROUTER),
        (OPTION_DNS_SERVER, DNS_SERVER),
        (OPTION_LEASE_TIME, struct.pack('!I', LEASE_TIME)),
        (OPTION_DHCP_SERVER_ID, socket.inet_aton(SERVER_IP)),
        (OPTION_END, b'')
    ]

    pos = 0x32
    for code, value in options:
        packet[pos] = code
        if isinstance(value, str):
            packet[pos + 1:pos + 1 + len(value)] = value.encode()
            pos += len(value)
        else:
            packet[pos + 1:pos + 5] = value
            pos += 4
        pos += 1

    return bytes(packet[:pos])

# Handle DHCP messages
def handle_dhcp(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        if data[0] == 1:  # DHCP Discover
            xid = struct.unpack_from('!I', data, 4)[0]
            mac_addr = data[0x2c:0x32]
            print(f"Received DHCP Discover from {mac_addr}")
            
            # Create DHCP offer packet
            offer_packet = create_offer(xid, mac_addr)
            print(f"Offering IP address to {mac_addr}")

            # Send offer packet
            sock.sendto(offer_packet, ('255.255.255.255', 67))
        elif data[0] == 3:  # DHCP Request
            xid = struct.unpack_from('!I', data, 4)[0]
            mac_addr = data[0x2c:0x32]
            print(f"Received DHCP Request from {mac_addr}")

            # Create DHCP ACK packet
            ack_packet = create_offer(xid, mac_addr)
            ack_packet = ack_packet.replace(bytes([DHCP_OFFER]), bytes([DHCP_ACK]))
            print(f"Sending DHCP ACK to {mac_addr}")

            # Send ACK packet
            sock.sendto(ack_packet, ('255.255.255.255', 67))

# Main function
def main():
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 67))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    print("DHCP server started. Listening for DHCP requests...")

    # Handle DHCP messages
    handle_dhcp(sock)

if __name__ == "__main__":
    main()