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

    def send(self, bloom_filter):
        with self.sendlock:
            _, write_ready, _ = select.select([], [self.socket], [], self.timeout)
            if not write_ready:
                return self.SocketStatus.TIMEOUT
            self.socket.sendall(bloom_filter)
            return self.SocketStatus.OK

    def recv(self, bloom_size=100 * 1024 * 8):
        result = b''
        with self.recvlock:
            read_ready, _, _ = select.select([self.socket], [], [], self.timeout)
            if not read_ready:
                return (self.SocketStatus.TIMEOUT, b'')
            result = self.socket.recv(bloom_size)
        if not result:
            return (self.SocketStatus.DISCONNECTED, b'')
        return (self.SocketStatus.OK, result)
    
    def close(self):
            self.socket.close()
