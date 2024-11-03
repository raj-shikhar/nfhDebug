import threading
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from scapy.all import*
error_lock = threading.Lock()
error = []
def ftp_server(UserName, PassWord, directory):
    try:
        authorizer = DummyAuthorizer()
        authorizer.add_user(UserName, PassWord, directory, perm='elradfmw')

        handler = FTPHandler
        handler.authorizer = authorizer

        server = FTPServer(('0.0.0.0', 21), handler)
        server.serve_forever(timeout=60)
    except Exception as e:
        with error_lock:
            error.append("FTP:" + str(e))

def start_ftp_server(UserName, PassWord, directory):
    global ftp_server_thread
    ftp_server_thread = threading.Thread(target=ftp_server, args=(UserName, PassWord, directory))
    ftp_server_thread.start()

def process(packet):
    if Raw in packet:
        payload = packet[Raw].load
        lines = payload.split(b'\r\n')
        UserName = None
        PassWord = None
        directory = []

        for line in lines:
            if line.startswith(b'USER'):
                UserName = line.split(b' ')[1].decode()
            elif line.startswith(b'PASS'):
                PassWord = line.split(b' ')[1].decode()
            else:
                directory.append(line.decode())

        start_ftp_server(UserName, PassWord, directory)
        ftp_server_thread.join()  # Wait for the FTP server thread to finish

        with error_lock:
            return error[:]




