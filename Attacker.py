import socket

def simple_broadcast_receiver(udp_broadcast_port=37020):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', udp_broadcast_port))
    
    while True:
        print("Listening for broadcast messages...")
        data, addr = sock.recvfrom(1024)
        print(f"Data received from {addr}: {data.decode()}")

if __name__ == "__main__":
    simple_broadcast_receiver()
