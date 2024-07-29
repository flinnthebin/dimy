import os
import signal
import socket
import threading
import time
import subprocess
from ThreadSafeSocket import ThreadSafeSocket

#####################
#                   #
#      CONFIG       #
#                   #
#####################

ATK_HOST='192.168.0.157'
ATK_PORT=55000

#####################
#                   #
#      CONFIG       #
#                   #
#####################

class Attacker:
    def __init__(self, attacker_host=ATK_HOST, attacker_port=ATK_PORT, backend_pid=None):
        self.host = attacker_host
        self.port = attacker_port
        self.backend_pid = backend_pid
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print(f"\033[91mATTACKER INITIALIZED\033[0m {self.host}:{self.port}")

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
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"\033[91mATTACKER AWAIT\033[0m {self.host}:{self.port}")

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
from Bloom import BloomFilter
import time
from collections import deque

class BFMan:
    def __init__(self, dbf_duration=90, max_dbfs=6):
        self.dbf_duration = dbf_duration
        self.max_dbfs = max_dbfs
        self.dbfs = deque()
        self.current_dbf = BloomFilter()
        self.start_time = time.time()
        self.qbf_start_time = self.start_time
        self.qbf = BloomFilter()
        self.dbf_counter = 1
        self.qbf_created = False
        print(f"\033[36mDBF CREATED\033[0m (1 of {self.max_dbfs})")

    def add_enc_id(self, enc_id):
        current_time = time.time()
        if current_time - self.start_time >= self.dbf_duration:
            self._rotate_dbf()
        self.current_dbf.add(enc_id)

    def _rotate_dbf(self):
        if len(self.dbfs) >= self.max_dbfs:
            self.dbfs.popleft()
        self.dbfs.append(self.current_dbf)
        self.current_dbf = BloomFilter()
        self.dbf_counter += 1
        if self.dbf_counter > self.max_dbfs:
            self.dbf_counter = 1
        print(f"\033[36mDBF CREATED\033[0m ({self.dbf_counter} of {self.max_dbfs})")
        self.start_time = time.time()

    def contains(self, enc_id):
        for dbf in self.dbfs:
            if enc_id in dbf:
                return True
        return enc_id in self.current_dbf or enc_id in self.qbf

    def query_filter(self):
        current_time = time.time()
        if current_time - self.qbf_start_time >= self.dbf_duration * self.max_dbfs:
            print(f"\033[93mCREATING QBF\033[0m")
            self.qbf = BloomFilter()
            for dbf in self.dbfs:
                for i in range(dbf.size):
                    if dbf.bit_array[i]:
                        self.qbf.bit_array[i] = 1
            self.dbfs.clear()
            self.qbf_created = True
            self.qbf_start_time = current_time
            print(f"\033[36mQBF CREATED\033[0m")

    def is_qbf_created(self):
        if self.qbf_created:
            self.qbf_created = False
            return True
        return False

    def contact_filter(self):
        print(f"\033[93mCREATING CBF\033[0m")
        cbf = BloomFilter()
        for dbf in self.dbfs:
            for i in range(dbf.size):
                if dbf.bit_array[i]:
                    cbf.bit_array[i] = 1
        for i in range(self.current_dbf.size):
            if self.current_dbf.bit_array[i]:
                cbf.bit_array[i] = 1
        print(f"\033[36mCBF CREATED\033[0m")
        return cbf
import bitarray
import hashlib

class BloomFilter:
    def __init__(self, size=100 * 1024 * 8, num_hashes=3):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bitarray.bitarray(size)
        self.bit_array.setall(0)

    def _hashes(self, enc_id):
        enc_id = enc_id.encode('utf-8')
        return [int(hashlib.sha256(enc_id + str(i).encode('utf-8')).hexdigest(), 16) % self.size for i in range(self.num_hashes)]

    def add(self, enc_id):
        for hash in self._hashes(enc_id):
            self.bit_array[hash] = 1

    def __contains__(self, enc_id):
        return all(self.bit_array[hash] for hash in self._hashes(enc_id))
from BFMan import BFMan
from ThreadSafeSocket import ThreadSafeSocket
import hashlib
import json
import secrets
import shamirs
import socket
import time
import threading
import signal
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

#####################
#                   #
#      CONFIG       #
#                   #
#####################

UDP_HOST='192.168.0.255'
UDP_PORT=37020
SRV_HOST='192.168.0.157'
SRV_PORT=55000

#####################
#                   #
#      CONFIG       #
#                   #
#####################

class Node:
    def __init__(self, udp_broadcast_host=UDP_HOST, udp_broadcast_port=UDP_PORT, backend_host=SRV_HOST,
                 backend_port=SRV_PORT, mersenne_prime=(2**607) - 1):
        self.mersenne_prime = mersenne_prime
        self.n = 3
        self.k = 5
        self.udp_broadcast_host = udp_broadcast_host
        self.udp_broadcast_port = udp_broadcast_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', self.udp_broadcast_port))
        self.received_shares = {}
        self.generated_ephids = set()
        self.generated_hashes = set()
        self.reconstructed_ephids = set()
        self.bf_man = BFMan()
        self.isolated = threading.Event()
        signal.signal(signal.SIGQUIT, self.handle_signal)

    @staticmethod
    def string_encode(i):
        return i.to_bytes((i.bit_length() + 7) // 8, "big")

    @staticmethod
    def derive_private_key(ephemeral_id):
        diffie_hellman = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ephemeral key',
            backend=default_backend()
        )
        private_key_bytes = diffie_hellman.derive(ephemeral_id)
        return X25519PrivateKey.from_private_bytes(private_key_bytes)
 
    def generate_ephemeral_id(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        ephID = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return ephID, private_key
    
    def share_ephemeral_id(self, ephemeral_id):
        return shamirs.shares(
            int.from_bytes(ephemeral_id, "big"), self.k, modulus=self.mersenne_prime, threshold=self.n
        )

    def format_share(self, share, num_chars=10):
        share_idx = str(share.index)[:num_chars]
        share_val = str(share.value)[:num_chars]
        return f"share({share_idx}, {share_val})"

    def format_shares(self, shares, num_chars=3):
        formatted_shares = [self.format_share(share, num_chars) for share in shares]
        return f"\033[97mGENERATED Shares:\033[0m [{', '.join(formatted_shares)}]"

    def drop_share(self):
        return secrets.SystemRandom().random() < 0.5

    def parse_share(self, share_str):
        share_str = share_str.strip("share()")
        x, y, modulus = map(int, share_str.split(", "))
        return shamirs.share(x, y, modulus)

    def parse_message(self, message):
        share_str, ephemeral_hash = message.split("| Hash: ")
        share = self.parse_share(share_str.strip())
        ephemeral_hash = ephemeral_hash.strip()
        return share, ephemeral_hash

    def broadcast_shares(self):
        while not self.isolated.is_set():
            ephemeral_id, private_key = self.generate_ephemeral_id()
            self.generated_ephids.add(ephemeral_id.hex())
            ephemeral_hash = hashlib.sha256(ephemeral_id).hexdigest()
            self.generated_hashes.add(ephemeral_hash)
            print(f"\033[97mGENERATED EphID\033[0m #{ephemeral_id.hex()[:10]}")
            shares = self.share_ephemeral_id(ephemeral_id)
            print(self.format_shares(shares))
            for i, share in enumerate(shares, start=1):
                formatted_share = self.format_share(share)
                if not self.drop_share():
                    message = f"{share} | Hash: {ephemeral_hash}"
                    self.sock.sendto(message.encode(), (self.udp_broadcast_host, self.udp_broadcast_port))
                    print(f"\033[92mBROADCAST\033[0m Hash: {ephemeral_hash[:10]} | Share: {formatted_share}")
                else:
                    print(f"\033[91mDROPPED\033[0m Hash: {ephemeral_hash[:10]} | Share: {formatted_share}")
                time.sleep(3)
    
    def listen_for_shares(self):
        while not self.isolated.is_set():
            data, _ = self.sock.recvfrom(1024)
            message = data.decode()
            share, ephemeral_hash = self.parse_message(message)
            if ephemeral_hash in self.reconstructed_ephids:
                continue
            if ephemeral_hash not in self.received_shares:
                self.received_shares[ephemeral_hash] = []
            self.received_shares[ephemeral_hash].append(share)
            if ephemeral_hash not in self.generated_hashes:
                share_count = len(self.received_shares[ephemeral_hash])
                print(f"\033[93mRECEIVED \033[0mHash: {ephemeral_hash[:10]} | Shares Received: {share_count}")
            if len(self.received_shares[ephemeral_hash]) == self.n:
                print(f"\033[94mATTEMPTING RECONSTRUCTION\033[0m Hash: {ephemeral_hash[:10]} with {self.n} shares")
                self.reconstruction(ephemeral_hash)

    def reconstruction(self, ephemeral_hash):
        # Ephemeral ID
        shares = self.received_shares[ephemeral_hash]
        interpolate = shamirs.interpolate(shares, threshold=self.n)
        ephemeral_bytes = self.string_encode(interpolate)
        re_hash = hashlib.sha256(ephemeral_bytes).hexdigest()
        print(f"\033[94mVERIFYING RECONSTRUCTION\033[0m Hash: {ephemeral_hash[:10]} | Reconstructed Hash: {re_hash[:10]}")
        if re_hash == ephemeral_hash:
            print(f"\033[94mRECONSTRUCTED\033[0m EphID: {ephemeral_bytes.hex()[:10]} | Hash: {ephemeral_hash[:10]}")
            self.reconstructed_ephids.add(ephemeral_hash)
            # Encounter ID
            try:
                ephID_public_key = X25519PublicKey.from_public_bytes(ephemeral_bytes)
                derived_private_key = self.derive_private_key(ephemeral_bytes)
                shared_key = derived_private_key.exchange(ephID_public_key)
                enc_id = hashlib.sha256(shared_key).digest()
                print(f"\033[95mCOMPUTED\033[0m EncID: {enc_id.hex()[:10]}")
                self.bf_man.add_enc_id(enc_id.hex())
                print(f"\033[95mENCODED TO DBF\033[0m Discarding EncID: {enc_id.hex()[:10]}")
                one_bits_indices = [i for i, bit in enumerate(self.bf_man.current_dbf.bit_array) if bit]
                print(f"\033[95mDBF STATE\033[0m {one_bits_indices}")
            except Exception as e:
                print(f"\033[91mERROR\033[0m Failed to compute EncID: {str(e)}")
        else:
            print(f"\033[91mFAILED\033[0m Hash: {ephemeral_hash[:10]} | \033[91m Hash Mismatch \033[0m")

    def send_qbf_to_backend(self, qbf):
        try:
            with socket.create_connection((self.backend_host, self.backend_port), timeout=10) as sock:
                ts_socket = ThreadSafeSocket(sock, timeout=10)
                type_designator = "QBF"
                status = ts_socket.send(type_designator.encode().strip())
                if status != ThreadSafeSocket.SocketStatus.OK:
                    print(f"\033[91mQBF TYPE DESIGNATOR SEND FAILED\033[0m Status: {status}")
                    return
                status = ts_socket.send(qbf)
                if status == ThreadSafeSocket.SocketStatus.OK:
                    print(f"\033[95mQBF SENT\033[0m to {self.backend_host}:{self.backend_port}")
                    status, response = ts_socket.recv()
                    if status == ThreadSafeSocket.SocketStatus.OK:
                        print(f"\033[95mRESPONSE RECEIVED\033[0m: {response.decode()}")
                        if response.decode() == "\033[92mMATCHED\033[0m":
                            self.isolated.set()
                            print(f"\033[93mCOVID CONTACT CONFIRMED\033[0m Isolating Node")
                else:
                    print(f"\033[91mQBF SEND FAILED\033[0m Status: {status}")
        except Exception as e:
            print(f"\033[91mERROR\033[0m Failed to send QBF: {str(e)}")

    def send_cbf_to_backend(self, cbf):
        try:
            with socket.create_connection((self.backend_host, self.backend_port), timeout=10) as sock:
                ts_socket = ThreadSafeSocket(sock, timeout=10)
                type_designator = "CBF"
                status = ts_socket.send(type_designator.encode().strip())
                if status != ThreadSafeSocket.SocketStatus.OK:
                    print(f"\033[91mCBF TYPE DESIGNATOR SEND FAILED\033[0m Status: {status}")
                    return
                status = ts_socket.send(cbf)
                if status == ThreadSafeSocket.SocketStatus.OK:
                    print(f"\033[95mCBF SENT\033[0m to {self.backend_host}:{self.backend_port}")
                    status, response = ts_socket.recv()
                    if status == ThreadSafeSocket.SocketStatus.OK:
                        print(f"\033[95mRESPONSE RECEIVED\033[0m: {response.decode()}")
                    else:
                        print(f"\033[91mRESPONSE RECEIPT FAILED\033[0m Status: {status}")
                else:
                    print(f"\033[91mCBF SEND FAILED\033[0m Status: {status}")
        except Exception as e:
            print(f"\033[91mERROR\033[0m Failed to send CBF: {str(e)}")

    def query_filter(self):
        while not self.isolated.is_set():
            self.bf_man.query_filter()
            if self.bf_man.is_qbf_created():
                qbf = self.bf_man.qbf.bit_array.tobytes()
                self.send_qbf_to_backend(qbf)
            time.sleep(1)

    def handle_signal(self, signum, frame):
        print(f"\033[93mCOVID CONTACT CONFIRMED\033[0m Isolating Node")
        self.isolated.set()
        cbf = self.bf_man.contact_filter().bit_array.tobytes()
        self.send_cbf_to_backend(cbf)
        print(f"\033[95mCBF SENT\033[0m | Node Isolated")

if __name__ == "__main__":
    node = Node()
    broadcast = threading.Thread(target=node.broadcast_shares)
    broadcast.start()
    query_filter = threading.Thread(target=node.query_filter)
    query_filter.start()
    node.listen_for_shares()
import bitarray
import socket
import threading
from ThreadSafeSocket import ThreadSafeSocket

#####################
#                   #
#      CONFIG       #
#                   #
#####################

SRV_HOST='192.168.0.157'
SRV_PORT=55000

#####################
#                   #
#      CONFIG       #
#                   #
#####################

class BackendServer:
    def __init__(self, host=SRV_HOST, port=SRV_PORT):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.received_qbf = set()
        print(f"\033[92mSERVER AWAIT\033[0m {self.host}:{self.port}")

    def get_max_qbf_size(self):
        if not self.received_qbf:
            return 0
        return max(len(qbf) for qbf in self.received_qbf)

    def pad_bloom_filter(self, bloom_filter_bytes):
        max_qbf_size = self.get_max_qbf_size()
        if len(bloom_filter_bytes) < max_qbf_size:
            padding_length = max_qbf_size - len(bloom_filter_bytes)
            bloom_filter_bytes += b'\x00' * padding_length
        return bloom_filter_bytes

    def check_cbf(self, cbf):
        cbf_bits = bitarray.bitarray()
        cbf_bits.frombytes(cbf)
        cbf_count = cbf_bits.count()
        
        if cbf_count == 0:
            return False

        for qbf in self.received_qbf:
            qbf_bits = bitarray.bitarray()
            qbf_bits.frombytes(qbf)
            qbf_count = qbf_bits.count()

            matching_bits = (cbf_bits & qbf_bits).count()
            match_percentage = (matching_bits / cbf_count) * 100
            if match_percentage >= 10:
                return True

        return False

    def handle_client(self, client_socket):
        ts_socket = ThreadSafeSocket(client_socket, timeout=10)
        status, type_data = ts_socket.recv()
        if status != ThreadSafeSocket.SocketStatus.OK:
            print(f"\033[91mRECEIPT FAILED\033[0m Status: {status}")
            client_socket.close()
            return
        type_designator = type_data.decode()[:3]
        print(f"\033[93mTYPE DESIGNATOR RECEIVED\033[0m: {type_designator}")
        status, bf_data = ts_socket.recv_all()
        if status != ThreadSafeSocket.SocketStatus.OK:
            print(f"\033[91mRECEIPT FAILED\033[0m Status: {status}")
            client_socket.close()
            return
        if type_designator == "QBF":
            print(f"\033[93mQBF RECEIVED\033[0m Length: {len(bf_data)} bytes")
            self.received_qbf.add(bf_data)
            print(f"\033[92mQBF ADDED TO CONTACT DATABASE\033[0m")
        elif type_designator == "CBF":
            print(f"\033[93mCBF RECEIVED\033[0m Length: {len(bf_data)} bytes")
            print(f"\033[93mTESTING CBF AGAINST QBF DATABASE\033[0m Length: {len(bf_data)} bytes")
            padded_cbf = self.pad_bloom_filter(bf_data)
            matched = self.check_cbf(padded_cbf)
            response = "\033[92mMATCHED\033[0m" if matched else "\033[91mNOT MATCHED\033[0m"
            print(f"\033[92mRESPONSE SENT\033[0m Result: {response}")
            ts_socket.send(response.encode())
        else:
            print(f"\033[91mUNKNOWN TYPE DESIGNATOR\033[0m: {type_designator}")
        client_socket.close()

    def start(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
    backend_server = BackendServer()
    backend_server.start()
import select
import socket
from threading import RLock
from enum import IntEnum

class ThreadSafeSocket:
    class SocketStatus(IntEnum):
        DISCONNECTED = 0
        OK = 1
        TIMEOUT = 2

    def __init__(self, socket, timeout):
        self.socket = socket
        self.socket.setblocking(0)
        self.recvlock = RLock()
        self.sendlock = RLock()
        self.timeout = timeout

    def send(self, data):
        with self.sendlock:
            _, write_ready, _ = select.select([], [self.socket], [], self.timeout)
            if not write_ready:
                return self.SocketStatus.TIMEOUT
            self.socket.sendall(data)
            return self.SocketStatus.OK

    def recv(self, buffer_size=1024):
        result = b''
        with self.recvlock:
            read_ready, _, _ = select.select([self.socket], [], [], self.timeout)
            if not read_ready:
                return (self.SocketStatus.TIMEOUT, b'')
            result = self.socket.recv(buffer_size)
        if not result:
            return (self.SocketStatus.DISCONNECTED, b'')
        return (self.SocketStatus.OK, result)
    
    def recv_all(self):
        result = b''
        with self.recvlock:
            while True:
                read_ready, _, _ = select.select([self.socket], [], [], self.timeout)
                if not read_ready:
                    print(f"\033[91mTIMEOUT\033[0m while waiting for data")
                    return (self.SocketStatus.TIMEOUT, result)
                chunk = self.socket.recv(102400)
                if not chunk:
                    print(f"\033[91mDISCONNECTED\033[0m while receiving data")
                    return (self.SocketStatus.DISCONNECTED, result)
                result += chunk
                if len(chunk) > 1024:
                    break
        return (self.SocketStatus.OK, result)

    def close(self):
        self.socket.close()
