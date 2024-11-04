import threading
import socket
import logging
from scapy.all import IP, TCP, UDP, Raw
import DHCP, WEBRequest

# Setting up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler = logging.FileHandler('error_logs.log')
file_handler.setLevel(logging.ERROR)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

protocol_handler = {
    80: WEBRequest,                # FTP
    67: DHCP,                 # DHCP
                  # POP3S
    # Add more protocols and their corresponding handlers here
}

def packet_process(packet):
    packet = IP(packet)

    if IP in packet:
        ip_packet = packet[IP]
        dst_port = None

        if TCP in ip_packet:
            tcp_packet = ip_packet[TCP]
            dst_port = tcp_packet.dport
        elif UDP in ip_packet:
            udp_packet = packet[UDP]
            dst_port = udp_packet.dport
        
        if dst_port:
            handler = protocol_handler.get(dst_port)
            
            if handler:
                try:
                    result = handler.process(packet)
                    logging.info(result)
                except Exception as e:
                    logger.error(f"Error processing packet for port {dst_port}: {str(e)}")
            else: 
                logger.error(f"No handler found for destination port {dst_port}")

def handle_client(client_socket, address):
   while True:
       data = client_socket.recv(4096)
       if not data:
           client_socket.close()
           break
       packet_process(data)

def receive():
    print('Server is running and listening.....')
    host = '0.0.0.0'
    port = 5555
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    while True:
        client, address = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client, address))
        client_thread.start()



if __name__ == "__main__":
    receive()