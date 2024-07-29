import os
import signal
import socket
import threading
import time
import subprocess
from ThreadSafeSocket import ThreadSafeSocket

class Attacker:
    def __init__(self, attacker_host='192.168.0.157', attacker_port=55000, backend_pid=None):
        self.attacker_host = attacker_host
        self.attacker_port = attacker_port
        self.backend_pid = backend_pid
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print(f"\033[91mATTACKER INITIALIZED\033[0m {self.attacker_host}:{self.attacker_port}")

    def stop_backend_server(self):
        if self.backend_pid:
            os.kill(self.backend_pid, signal.SIGINT)
            print(f"\033[93mBACKEND SERVER STOPPED\033[0m PID: {self.backend_pid}")

    def simulate_dos_attack(self):
            print(f"\033[91mLAUNCHING DoS ATTACK\033[0m")
            for i in range(5):
                print(f"\033[93mDoS ATTACK\033[0m Packet {i+1}")
                time.sleep(0.5)
            self.stop_backend_server()
            print(f"\033[92mDoS ATTACK COMPLETE\033[0m")
            time.sleep(3)

    def start_attacker_server(self):
        self.server_socket.bind((self.attacker_host, self.attacker_port))
        self.server_socket.listen(5)
        print(f"\033[91mATTACKER AWAIT\033[0m {self.attacker_host}:{self.attacker_port}")

    def handle_client(self, client_socket):
        ts_socket = ThreadSafeSocket(client_socket, timeout=10)
        status, data = ts_socket.recv()
        if status == ThreadSafeSocket.SocketStatus.OK:
            if len(data) == 102400:
                print(f"\033[95mINTERCEPTED QBF\033[0m Length: {len(data)} bytes")
            else:
                print(f"\033[95mINTERCEPTED CBF\033[0m Length: {len(data)} bytes")
                response = "\033[92mMATCHED\033[0m"
                print(f"\033[92mRESPONSE SENT\033[0m Result: {response}")
                ts_socket.send(response.encode())
        else:
            print(f"\033[91mRECEIPT FAILED\033[0m Status: {status}")
        client_socket.close()

    def start(self):
        self.simulate_dos_attack()
        self.start_attacker_server()
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

def get_backend_pid():
    try:
        result = subprocess.run(['ps', 'aux'], stdout=subprocess.PIPE)
        output = result.stdout.decode()
        for line in output.splitlines():
            if 'python3 DimyServer.py' in line and 'grep' not in line:
                return int(line.split()[1])
    except Exception as e:
        print(f"\033[91mERROR\033[0m Failed to get backend PID: {str(e)}")
        return None

if __name__ == "__main__":
    backend_pid = get_backend_pid()
    if backend_pid:
        attacker = Attacker(backend_pid=backend_pid)
        attacker.start()
    else:
        print(f"\033[91mERROR\033[0m Backend server PID not found")
