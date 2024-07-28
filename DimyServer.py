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
                print(f"\033[93mQBF RECEIVED\033[0m Length: {len(data)} bytes")
                self.received_qbf.add(data)
                print(f"\033[92mQBF ADDED TO CONTACT DATABASE\033[0m")
            else:
                print(f"\033[93mCBF RECEIVED\033[0m Length: {len(data)} bytes")
                print(f"\033[93mTESTING CBF AGAINST QBF DATABASE\033[0m Length: {len(data)} bytes")
                padded_cbf = self.pad_bloom_filter(data)
                matched = self.check_cbf(padded_cbf)
                response = "0\033[92mMATCHED\033[0m" if matched else "\033[91mNOT MATCHED\033[0m"
                print(f"\033[92mRESPONSE SENT\033[0m Result: {response}")
                ts_socket.send(response.encode())
        else:
            print(f"\033[91mRECEIPT FAILED\033[0m Status: {status}")
        client_socket.close()

    def pad_bloom_filter(self, bloom_filter_bytes, target_size=102400):
        if len(bloom_filter_bytes) < target_size:
            padding_length = target_size - len(bloom_filter_bytes)
            bloom_filter_bytes += b'\x00' * padding_length
        return bloom_filter_bytes

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
