import time
import uuid
import shamirs
import socket

# CONFIG 
udp_broadcast_ip = '127.0.0.1'
udp_broadcast_port = 8080 
mersenne_prime = (2**607) - 1
# UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

def int_encode(s):
    return int.from_bytes(s.encode(), "big")

def string_encode(i):
    return i.to_bytes((i.bit_length() + 7) // 8, "big").decode()

while True:
    alpha_key, bravo_key = str(uuid.uuid4()), str(uuid.uuid4())
    ephemeral_id = alpha_key + "-" + bravo_key
    shares = shamirs.shares(
        int_encode(ephemeral_id), 5, modulus=mersenne_prime, threshold=3
    )

    for share in shares:
        sock.sendto(str(share).encode(), (udp_broadcast_ip, udp_broadcast_port))
        time.sleep(3)

    reconstructed_int = shamirs.interpolate(shares[:3])
    reconstructed_ephemeral_id = string_encode(reconstructed_int)
