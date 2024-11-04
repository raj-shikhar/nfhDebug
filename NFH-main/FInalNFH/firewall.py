from scapy.all import *
from scapy.all import IP, TCP, UDP, Raw, send, sr1  # Import necessary layers
import sqlite3
import hashlib


# Create a database connection for the rules
conn_rules = sqlite3.connect("rules.db")
cursor_rules = conn_rules.cursor()
cursor_rules.execute('''CREATE TABLE IF NOT EXISTS rules (ID INTEGER PRIMARY KEY, hash TEXT NOT NULL)''')

# Create a database connection for the content hash
conn_content = sqlite3.connect("content.db")
cursor_content = conn_content.cursor()
cursor_content.execute('''CREATE TABLE IF NOT EXISTS content (ID INTEGER PRIMARY KEY, hash TEXT NOT NULL)''')


def get_Rule_from_table(data, cursor, table):
    md5_hash = hashlib.md5(data.encode('utf-8')).hexdigest()
    cursor.execute("SELECT * FROM {} WHERE hash=?".format(table), (md5_hash,))
    result = cursor.fetchone() 
    if result:
        return True
    return False

def packet_process(packet):
    if packet.haslayer(IP):
        ip_packet = packet[IP]
        dst_port = None

        if TCP in ip_packet:
            tcp_packet = ip_packet[TCP]
            dst_port = tcp_packet.dport
        elif UDP in ip_packet:
            udp_packet = packet[UDP]
            dst_port = udp_packet.dport
        
        if dst_port:
            src_ip = ip_packet.src
            dst_ip = ip_packet.dst
            src_port = ip_packet.sport
            mac_addr = packet.src
            protocol = ip_packet.proto
            if Raw in packet:
                payload = packet[Raw].load
            
            packet_info = f"{src_ip}:{dst_ip}:{src_port}:{dst_port}:{mac_addr}:{protocol}"
            packet_content = f"{payload}"
            
            attribute = (packet_info, packet_content)

            packet_info_rule = get_Rule_from_table(packet_info, cursor_rules, 'rules')
            packet_info_rule_content = get_Rule_from_table(packet_content, cursor_content, 'content')
            

            if packet_info_rule or packet_info_rule_content:
                return True,attribute
    return False()

