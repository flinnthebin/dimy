import hashlib
import threading
import socket
import secrets
import time
import shamirs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class Node:
    def __init__(self, udp_broadcast_ip='192.168.0.255', udp_broadcast_port=37020, mersenne_prime=(2**607) - 1):
        self.mersenne_prime = mersenne_prime
        self.n = 3
        self.k = 5
        self.udp_broadcast_ip = udp_broadcast_ip
        self.udp_broadcast_port = udp_broadcast_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', self.udp_broadcast_port))
        self.received_shares = {}
        self.generated_ephids = set()
        self.generated_hashes = set()
        self.reconstructed_ephids = set()

    @staticmethod
    def string_encode(i):
        return i.to_bytes((i.bit_length() + 7) // 8, "big")

    @staticmethod
    def derive_private_key(ephemeral_id):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ephemeral key',
            backend=default_backend()
        )
        private_key_bytes = hkdf.derive(ephemeral_id)
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
        return f"\033[97m GENERATED Shares:\033[0m [{', '.join(formatted_shares)}]"

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
        while True:
            ephemeral_id, private_key = self.generate_ephemeral_id()
            ephemeral_str = ephemeral_id.hex()
            self.generated_ephids.add(ephemeral_str)
            ephemeral_hash = hashlib.sha256(ephemeral_id).hexdigest()
            self.generated_hashes.add(ephemeral_hash)
            print(f"\033[97m GENERATED EphID \033[0m #{ephemeral_str[:10]}")
            shares = self.share_ephemeral_id(ephemeral_id)
            print(self.format_shares(shares))
            for i, share in enumerate(shares, start=1):
                formatted_share = self.format_share(share)
                if not self.drop_share():
                    message = f"{share} | Hash: {ephemeral_hash}"
                    self.sock.sendto(message.encode(), (self.udp_broadcast_ip, self.udp_broadcast_port))
                    print(f"\033[92m BROADCAST \033[0m Hash: {ephemeral_hash[:10]} | Share: {formatted_share}")
                else:
                    print(f"\033[91m DROPPED \033[0m Hash: {ephemeral_hash[:10]} | Share: {formatted_share}")
                time.sleep(2)
    
    def listen_for_shares(self):
        while True:
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
                print(f"\033[93m RECEIVED \033[0m Hash: {ephemeral_hash[:10]} | Shares Received: {share_count}")
            if len(self.received_shares[ephemeral_hash]) == self.n:
                print(f"\033[96m ATTEMPTING RECONSTRUCTION \033[0m Hash: {ephemeral_hash[:10]} with {self.n} shares")
                self.reconstruction(ephemeral_hash)

    def reconstruction(self, ephemeral_hash):
        # Reconstruct Ephemeral ID
        shares = self.received_shares[ephemeral_hash]
        interpolate = shamirs.interpolate(shares, threshold=self.n)
        ephemeral_bytes = self.string_encode(interpolate)
        re_hash = hashlib.sha256(ephemeral_bytes).hexdigest()
        print(f"\033[96m VERIFYING RECONSTRUCTION \033[0m Hash: {ephemeral_hash[:10]} | Reconstructed Hash: {re_hash[:10]}")
        if re_hash == ephemeral_hash:
            print(f"\033[94m RECONSTRUCTED \033[0m EphID: {ephemeral_bytes.hex()[:10]} | Hash: {ephemeral_hash[:10]}")
            self.reconstructed_ephids.add(ephemeral_hash)
            # Compute EncID after reconstructing EphID
            try:
                ephID_public_key = X25519PublicKey.from_public_bytes(ephemeral_bytes)
                derived_private_key = self.derive_private_key(ephemeral_bytes)
                shared_key = derived_private_key.exchange(ephID_public_key)
                # Derive EncID from the shared key
                enc_id = hashlib.sha256(shared_key).digest()
                enc_id_hex = enc_id.hex()
                print(f"\033[95m COMPUTED \033[0m EncID: {enc_id_hex[:10]}")
            except Exception as e:
                print(f"\033[91m ERROR \033[0m Failed to compute EncID: {str(e)}")
        else:
            print(f"\033[91m FAILED \033[0m Hash: {ephemeral_hash[:10]} | \033[91m Hash Mismatch \033[0m")

if __name__ == "__main__":
    node = Node()
    broadcast_thread = threading.Thread(target=node.broadcast_shares)
    broadcast_thread.start()
    node.listen_for_shares()
