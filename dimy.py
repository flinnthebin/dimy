from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import time
import uuid
import shamirs
import secrets
import socket

class Node:
    def __init__(self, udp_broadcast_ip='127.0.0.1', udp_broadcast_port=55000, mersenne_prime=(2**607) - 1):
        self.udp_broadcast_ip = udp_broadcast_ip
        self.udp_broadcast_port = udp_broadcast_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.mersenne_prime = mersenne_prime
        self.ephid_counter = self.generate_random_counter()
        self.n = 3
        self.k = 5

    def generate_random_counter(self):
        return secrets.randbelow(9000) + 1000

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

    def drop_share(self):
        return secrets.SystemRandom().random() < 0.5

    def broadcast_shares(self):
        while True:
            self.ephid_counter = self.generate_random_counter()
            ephemeral_id = self.generate_ephemeral_id()
            shares = self.share_ephemeral_id(ephemeral_id)

            for i, share in enumerate(shares, start=1):
                if not self.drop_share():
                    message = f"EphID #{self.ephid_counter}: {share}"
                    self.sock.sendto(message.encode(), (self.udp_broadcast_ip, self.udp_broadcast_port))
                else:
                    print(f"Dropped EphID #{self.ephid_counter}: {share}")
                time.sleep(3)

if __name__ == "__main__":
    node = Node()
    node.broadcast_shares()

