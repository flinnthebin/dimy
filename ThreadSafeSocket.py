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

    def send(self, data):
        with self.sendlock:
            _, write_ready, _ = select.select([], [self.socket], [], self.timeout)
            if not write_ready:
                return self.SocketStatus.TIMEOUT
            self.socket.sendall(data)
            return self.SocketStatus.OK

    def recv(self, buffer_size=1024):
        result = b''
        with self.recvlock:
            read_ready, _, _ = select.select([self.socket], [], [], self.timeout)
            if not read_ready:
                return (self.SocketStatus.TIMEOUT, b'')
            result = self.socket.recv(buffer_size)
        if not result:
            return (self.SocketStatus.DISCONNECTED, b'')
        return (self.SocketStatus.OK, result)
    
    def recv_all(self):
        result = b''
        with self.recvlock:
            while True:
                read_ready, _, _ = select.select([self.socket], [], [], self.timeout)
                if not read_ready:
                    print(f"\033[91mTIMEOUT\033[0m while waiting for data")
                    return (self.SocketStatus.TIMEOUT, result)
                chunk = self.socket.recv(102400)
                if not chunk:
                    print(f"\033[91mDISCONNECTED\033[0m while receiving data")
                    return (self.SocketStatus.DISCONNECTED, result)
                result += chunk
                if len(chunk) > 1024:
                    break
        return (self.SocketStatus.OK, result)

    def close(self):
        self.socket.close()
