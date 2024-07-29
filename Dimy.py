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

class Node:
    def __init__(self, udp_broadcast_ip='192.168.0.255', udp_broadcast_port=37020, backend_ip = '192.168.0.157',
                 backend_port = 55000, mersenne_prime=(2**607) - 1):
        self.mersenne_prime = mersenne_prime
        self.n = 3
        self.k = 5
        self.udp_broadcast_ip = udp_broadcast_ip
        self.udp_broadcast_port = udp_broadcast_port
        self.backend_ip = backend_ip
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
                    self.sock.sendto(message.encode(), (self.udp_broadcast_ip, self.udp_broadcast_port))
                    print(f"\033[92mBROADCAST\033[0m Hash: {ephemeral_hash[:10]} | Share: {formatted_share}")
                else:
                    print(f"\033[91mDROPPED\033[0m Hash: {ephemeral_hash[:10]} | Share: {formatted_share}")
                time.sleep(2)
    
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
            with socket.create_connection((self.backend_ip, self.backend_port), timeout=10) as sock:
                ts_socket = ThreadSafeSocket(sock, timeout=10)
                type_designator = "QBF"
                status = ts_socket.send(type_designator.encode().strip())
                if status != ThreadSafeSocket.SocketStatus.OK:
                    print(f"\033[91mQBF TYPE DESIGNATOR SEND FAILED\033[0m Status: {status}")
                    return
                status = ts_socket.send(qbf)
                if status == ThreadSafeSocket.SocketStatus.OK:
                    print(f"\033[95mQBF SENT\033[0m to {self.backend_ip}:{self.backend_port}")
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
            with socket.create_connection((self.backend_ip, self.backend_port), timeout=10) as sock:
                ts_socket = ThreadSafeSocket(sock, timeout=10)
                type_designator = "CBF"
                status = ts_socket.send(type_designator.encode().strip())
                if status != ThreadSafeSocket.SocketStatus.OK:
                    print(f"\033[91mCBF TYPE DESIGNATOR SEND FAILED\033[0m Status: {status}")
                    return
                status = ts_socket.send(cbf)
                if status == ThreadSafeSocket.SocketStatus.OK:
                    print(f"\033[95mCBF SENT\033[0m to {self.backend_ip}:{self.backend_port}")
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
