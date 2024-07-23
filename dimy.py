import hashlib
import threading
import socket
import secrets
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
import shamirs

class Node:
    def __init__(self, udp_broadcast_ip='192.168.0.255', udp_broadcast_port=37020, mersenne_prime=(2**607) - 1):
        self.mersenne_prime = mersenne_prime
        self.n = 3
        self.k = 5
        self.private_key = X25519PrivateKey.generate()
        self.udp_broadcast_ip = udp_broadcast_ip
        self.udp_broadcast_port = udp_broadcast_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', self.udp_broadcast_port))
        self.received_shares = {}
        self.generated_ephids = set()
        self.reconstructed_ephids = set()

    @staticmethod
    def int_encode(s):
        return int.from_bytes(s.encode(), "big")

    @staticmethod
    def string_encode(i):
        return i.to_bytes((i.bit_length() + 7) // 8, "big")

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

    def format_share(self, share, num_chars=3):
        share_idx = str(share.index)[:num_chars]
        share_val = str(share.value)[:num_chars]
        return f"share({share_idx}, {share_val})"

    def format_shares(self, shares, num_chars=3):
        formatted_shares = [self.format_share(share, num_chars) for share in shares]
        return f"\033[97m GENERATED Shares:\033[0m [{', '.join(formatted_shares)}]"

    def drop_share(self):
        return secrets.SystemRandom().random() < 0.5

    def broadcast_shares(self):
        while True:
            ephemeral_id, private_key = self.generate_ephemeral_id()
            ephemeral_str = ephemeral_id.hex()
            self.generated_ephids.add(ephemeral_str)
            print(f"\033[97m GENERATED EphID \033[0m #{ephemeral_str[:10]}")
            shares = self.share_ephemeral_id(ephemeral_id)
            print(self.format_shares(shares))
            ephemeral_hash = hashlib.sha256(ephemeral_id).hexdigest()
            for i, share in enumerate(shares, start=1):
                formatted_share = self.format_share(share)
                if not self.drop_share():
                    message = f"EphID #{ephemeral_str}: {share} | Hash: {ephemeral_hash}"
                    self.sock.sendto(message.encode(), (self.udp_broadcast_ip, self.udp_broadcast_port))
                    print(f"\033[92m BROADCAST \033[0m EphID #{ephemeral_str[:10]}: {formatted_share} | Hash: {ephemeral_hash[:10]}")
                else:
                    print(f"\033[91m DROPPED \033[0m EphID #{ephemeral_str[:10]}: {formatted_share} | Hash: {ephemeral_hash[:10]}")
                time.sleep(3)

    def listen_for_shares(self):
        while True:
            data, _ = self.sock.recvfrom(1024)
            message = data.decode()
            ephemeral_str, share, ephemeral_hash = self.parse_message(message)
            if ephemeral_str in self.reconstructed_ephids:
                continue
            if ephemeral_str not in self.received_shares:
                self.received_shares[ephemeral_str] = []
            if ephemeral_str not in self.generated_ephids:
                share_count = len(self.received_shares[ephemeral_str]) + 1
                print(f"\033[93m RECEIVED \033[0m EphID #{ephemeral_str[:10]} | Shares Received: {share_count}")
            self.received_shares[ephemeral_str].append((share, ephemeral_hash))
            if len(self.received_shares[ephemeral_str]) >= self.n:
                self.reconstruct_ephemeral_id(ephemeral_str)

    def parse_message(self, message):
        parts = message.split("| Hash: ")
        ephemeral_str, share_str = parts[0].split(": ")
        ephemeral_str = ephemeral_str.split("#")[1]
        share = self.parse_share(share_str.strip())
        ephemeral_hash = parts[1].strip()
        return ephemeral_str, share, ephemeral_hash

    def parse_share(self, share_str):
        share_str = share_str.strip("share()")
        x, y, modulus = map(int, share_str.split(", "))
        return shamirs.share(x, y, modulus)

    def reconstruct_ephemeral_id(self, ephemeral_str):
        if ephemeral_str in self.generated_ephids:
            return
        shares_hashes = self.received_shares[ephemeral_str]
        shares = [share for share, _ in shares_hashes]
        interpolate = shamirs.interpolate(shares, threshold=self.n)
        ephemeral_bytes = self.string_encode(interpolate)
        re_hash = hashlib.sha256(ephemeral_bytes).hexdigest()
        recv_hash = shares_hashes[0][1]
        if re_hash == recv_hash:
            print(f"\033[94m RECONSTRUCTED \033[0m EphID #{ephemeral_str[:10]}: {ephemeral_bytes.hex()} | Hash: {recv_hash[:10]}")
            self.reconstructed_ephids.add(ephemeral_str)
            # Compute EncID after reconstructing EphID
            ephID_bytes = self.string_encode(interpolate)
            ephID_public_key = X25519PublicKey.from_public_bytes(ephID_bytes)
            shared_key = self.private_key.exchange(ephID_public_key)
            x_at = secrets.token_bytes(32)
            enc_id = int.from_bytes(shared_key, "big") ^ int.from_bytes(x_at, "big")
            enc_id_hex = enc_id.to_bytes(32, "big").hex()
            print(f"\033[94m COMPUTED \033[0m EncID: {enc_id_hex}")
        else:
            print(f"\033[91m FAILED \033[0m EphID #{ephemeral_str[:10]} | \033[91m Hash Mismatch \033[0m")

if __name__ == "__main__":
    node = Node()
    broadcast_thread = threading.Thread(target=node.broadcast_shares)
    broadcast_thread.start()
    node.listen_for_shares()
