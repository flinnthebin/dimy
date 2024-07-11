import socket
import threading
import secrets
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import shamirs

class Node:
    def __init__(self, udp_broadcast_ip='127.0.0.1', mersenne_prime=(2**607) - 1):
        self.udp_broadcast_ip = udp_broadcast_ip
        self.udp_broadcast_port = self.find_free_port()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', self.udp_broadcast_port))
        self.mersenne_prime = mersenne_prime
        self.ephid_counter = self.generate_random_counter()
        self.n = 3
        self.k = 5
        self.received_shares = {}

    def find_free_port(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

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

    def listen_for_shares(self):
        while True:
            data, _ = self.sock.recvfrom(1024)
            message = data.decode()
            ephid_counter, share = self.parse_message(message)
            if ephid_counter not in self.received_shares:
                self.received_shares[ephid_counter] = []
            self.received_shares[ephid_counter].append(share)
            if len(self.received_shares[ephid_counter]) >= self.n:
                self.reconstruct_ephemeral_id(ephid_counter)

    def parse_message(self, message):
        parts = message.split(": ")
        ephid_counter = int(parts[0].split("#")[1])
        share_str = parts[1]
        share = self.parse_share(share_str)
        return ephid_counter, share

    def parse_share(self, share_str):
        # Extract the components of the share from the string
        share_str = share_str.strip("share()")
        x, y, modulus = map(int, share_str.split(", "))
        return shamirs.share(x, y, modulus)

    def reconstruct_ephemeral_id(self, ephid_counter):
        shares = self.received_shares[ephid_counter]
        ephID_int = shamirs.interpolate(shares, threshold=self.n)
        ephID_bytes = ephID_int.to_bytes((ephID_int.bit_length() + 7) // 8, byteorder='big')
        print(f"Reconstructed EphID #{ephid_counter}: {ephID_bytes.hex()}")

if __name__ == "__main__":
    node = Node()
    broadcast_thread = threading.Thread(target=node.broadcast_shares)
    broadcast_thread.start()
    node.listen_for_shares()
