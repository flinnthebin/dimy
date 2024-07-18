import socket
import threading
import secrets
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import shamirs

class Node:
    def __init__(self, udp_broadcast_ip='192.168.1.255', udp_broadcast_port=37020, mersenne_prime=(2**607) - 1):
        self.udp_broadcast_ip = udp_broadcast_ip
        self.udp_broadcast_port = udp_broadcast_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', self.udp_broadcast_port))
        self.mersenne_prime = mersenne_prime
        self.n = 3
        self.k = 5
        self.received_shares = {}
        self.generated_ephids = set()
        self.reconstructed_ephids = set()

    @staticmethod
    def int_encode(s):
        return int.from_bytes(s.encode(), "big")

    @staticmethod
    def string_encode(i):
        return i.to_bytes((i.bit_length() + 7) // 8, "big").hex()

    def generate_ephemeral_id(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        ephID = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return ephID

    def share_ephemeral_id(self, ephemeral_id):
        return shamirs.shares(
            int.from_bytes(ephemeral_id, "big"), self.k, modulus=self.mersenne_prime, threshold=self.n
        )

    def format_share(self, share, num_chars=3):
        x_str = str(share.index)[:num_chars]
        y_str = str(share.value)[:num_chars]
        return f"share({x_str}, {y_str})"

    def format_shares(self, shares, num_chars=3):
        formatted_shares = [self.format_share(share, num_chars) for share in shares]
        return f"Shares Generated: [{', '.join(formatted_shares)}]"

    def drop_share(self):
        return secrets.SystemRandom().random() < 0.5

    def broadcast_shares(self):
        while True:
            ephemeral_id = self.generate_ephemeral_id()
            ephid_str = ephemeral_id.hex()[:10]
            self.generated_ephids.add(ephid_str)
            print(f"EphID Generated: {ephid_str}")
            shares = self.share_ephemeral_id(ephemeral_id)
            print(self.format_shares(shares))

            for i, share in enumerate(shares, start=1):
                formatted_share = self.format_share(share)
                if not self.drop_share():
                    message = f"EphID #{ephid_str}: {share}"
                    self.sock.sendto(message.encode(), (self.udp_broadcast_ip, self.udp_broadcast_port))
                    print(f"\033[92m BROADCAST \033[0m EphID #{ephid_str}: {formatted_share}")
                else:
                    print(f"\033[91m DROPPED \033[0m EphID #{ephid_str}: {formatted_share}")
                time.sleep(3)

    def listen_for_shares(self):
        while True:
            data, _ = self.sock.recvfrom(1024)
            message = data.decode()
            ephid_str, share = self.parse_message(message)
            if ephid_str in self.reconstructed_ephids:
                continue
            if ephid_str not in self.received_shares:
                print(f"Message Received: {ephid_str}")
                self.received_shares[ephid_str] = []
            self.received_shares[ephid_str].append(share)
            if len(self.received_shares[ephid_str]) >= self.n:
                self.reconstruct_ephemeral_id(ephid_str)

    def parse_message(self, message):
        parts = message.split(": ")
        ephid_str = parts[0].split("#")[1]
        share_str = parts[1]
        share = self.parse_share(share_str)
        return ephid_str, share

    def parse_share(self, share_str):
        share_str = share_str.strip("share()")
        x, y, modulus = map(int, share_str.split(", "))
        return shamirs.share(x, y, modulus)

    def reconstruct_ephemeral_id(self, ephid_str):
        if ephid_str in self.generated_ephids:
            return
        shares = self.received_shares[ephid_str]
        ephID_int = shamirs.interpolate(shares, threshold=self.n)
        ephID_hex = self.string_encode(ephID_int)
        print(f"\033[94m RECONSTRUCTED \033[0m EphID #{ephid_str}: {ephID_hex}")
        self.reconstructed_ephids.add(ephid_str)

if __name__ == "__main__":
    node = Node()
    broadcast_thread = threading.Thread(target=node.broadcast_shares)
    broadcast_thread.start()
    node.listen_for_shares()
