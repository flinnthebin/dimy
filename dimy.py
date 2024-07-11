import time
import uuid
import shamirs
import secrets
import socket

class Node:
    def __init__(self, udp_broadcast_ip='127.0.0.1', udp_broadcast_port=55000, mersenne_prime=(2**607) - 1):
        self.udp_broadcast_ip = udp_broadcast_ip
        self.udp_broadcast_port = udp_broadcast_port
        self.mersenne_prime = mersenne_prime
        self.ephid_counter = 1

        # UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def int_encode(self, s):
        return int.from_bytes(s.encode(), "big")

    def string_encode(self, i):
        return i.to_bytes((i.bit_length() + 7) // 8, "big").decode()

    def generate_ephemeral_id(self):
        alpha_key, bravo_key = str(uuid.uuid4()), str(uuid.uuid4())
        return alpha_key + "-" + bravo_key

    def share_ephemeral_id(self, ephemeral_id):
        return shamirs.shares(
            self.int_encode(ephemeral_id), 5, modulus=self.mersenne_prime, threshold=3
        )

    def drop_share(self):
        return secrets.SystemRandom().random() < 0.5

    def broadcast_shares(self):
        while True:
            ephemeral_id = self.generate_ephemeral_id()
            shares = self.share_ephemeral_id(ephemeral_id)

            for i, share in enumerate(shares, start=1):
                if not self.drop_share():
                    message = f"EphID #{self.ephid_counter}: {share}"
                    self.sock.sendto(message.encode(), (self.udp_broadcast_ip, self.udp_broadcast_port))
                else:
                    print(f"Dropped EphID #{self.ephid_counter}: {share}")
                time.sleep(3)

            self.ephid_counter += 1

if __name__ == "__main__":
    node = Node()
    node.broadcast_shares()

################ REQUIRED LATER ####################################
#   reconstructed_int = shamirs.interpolate(shares[:3])
#   reconstructed_ephemeral_id = string_encode(reconstructed_int)

