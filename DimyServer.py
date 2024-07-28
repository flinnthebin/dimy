import bitarray
import socket
import threading
from ThreadSafeSocket import ThreadSafeSocket

class BackendServer:
    def __init__(self, host='192.168.0.157', port=55000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.received_qbf = set()
        print(f"\033[92m SERVER AWAIT \033[0m {self.host}:{self.port}")

    def handle_client(self, client_socket):
        ts_socket = ThreadSafeSocket(client_socket, timeout=10)
        status, data = ts_socket.recv()
        if status == ThreadSafeSocket.SocketStatus.OK:
            if len(data) == 102400:
                print(f"\033[92m QBF RECEIVED \033[0m Length: {len(data)} bytes")
                self.received_qbf.add(data)
            else:
                print(f"\033[92m CBF RECEIVED \033[0m Length: {len(data)} bytes")
                matched = self.check_cbf(data)
                response = "MATCHED" if matched else "NOT MATCHED"
                ts_socket.send(response.encode())
        else:
            print(f"\033[91m RECEIVE FAILED \033[0m Status: {status}")
        client_socket.close()

    def check_cbf(self, cbf):
        cbf_bits = bitarray.bitarray()
        cbf_bits.frombytes(cbf)
        cbf_count = cbf_bits.count()

        for qbf in self.received_qbf:
            qbf_bits = bitarray.bitarray()
            qbf_bits.frombytes(qbf)
            qbf_count = qbf_bits.count()

            matching_bits = (cbf_bits & qbf_bits).count()

            match_percentage = (matching_bits / cbf_count) * 100

            if match_percentage >= 50:
                return True

        return False

    def start(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
    backend_server = BackendServer()
    backend_server.start()
