# Copyright 2019 James Brown
# Modified 2023 by TechnoDot
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import array
import select
import socket
import struct
import logging
import threading
from datetime import datetime
from contextlib import contextmanager
from traceback import format_exception

from torpy.utils import recv_exact, register_logger
from torpy.client import TorClient

logger = logging.getLogger(__name__)

def L(message, level="info"):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [{level.upper()}] {message}")

def E(message):
    L(message, "error")

class SocksProxy:
    def __init__(self, server_sock, client_sock):
        self.server_sock = server_sock
        self.client_sock = client_sock

    def run(self):
        ssock = self.server_sock
        csock = self.client_sock
        _, port = csock.getsockname()
        csock.sendall(b"\x05\0\0\x01\x7f\0\0\x01" + struct.pack("!H", port))
        try:
            while True:
                r, _, _ = select.select([ssock, csock], [], [])
                if ssock in r: 
                    buf = ssock.recv(4096)
                    if len(buf) == 0:
                        break
                    csock.send(buf)
                if csock in r:
                    buf = csock.recv(4096)
                    if len(buf) == 0:
                        break
                    ssock.send(buf)
        except BaseException:
            E("Unknown socks error")
        finally:
            L("Closing server socket")
            ssock.close()
            L("Closing client socket")
            csock.close()

class SocksServer(object):
    def __init__(self, circuit):
        self.circuit = circuit
        self.listen_socket = None

    def __enter__(self):
        lsock = self.listen_socket = socket.socket(2, 1, 6)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind(("127.0.0.1", 1050))
        L(f"Socks5 proxy initialized at 127.0.0.1:1050")
        lsock.listen(0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.listen_socket.close()
        if exc_type:
            E("Exception in socks5 server: ")
            for line in format_exception(exc_type, exc_val, exc_tb):
                E(line.strip().rstrip("\r\n"))

    def start(self):
        while True:
            try:
                csock, caddr = self.listen_socket.accept()
            except BaseException:
                L("Closing socket by user request")
                raise
            L(f"Tor connected to {caddr}")
            Socks5(self.circuit, csock, caddr).start()

class Socks5(threading.Thread):
    def __init__(self, circuit, client_sock, client_addr):
        thread_name = "Socks-%s" % client_addr[1]
        super().__init__(name=thread_name)
        self.circuit = circuit
        self.client_sock = client_sock
        self.client_addr = client_addr

    def error(self, err=b"\x01\0"):
        try:
            self.client_sock.send(b"\x05" + err)
            self.client_sock.close()
            self.client_sock = None
        except BaseException:
            pass

    @contextmanager
    def create_socket(self, dest, port):
        L(f"Socket connecting to {dest}:{port}")
        with self.circuit.create_stream((dest, port)) as tor_stream:
            yield tor_stream.create_socket()
            L(f"Suspending stream #{tor_stream.id}")

    def run(self):
        csock = self.client_sock
        try:
            ver = csock.recv(1)
            if ver != b"\x05":
                return self.error(b"\xff")
            nmeth, = array.array("B", csock.recv(1))
            _ = recv_exact(csock, nmeth)
            csock.send(b"\x05\0")
            hbuf = recv_exact(csock, 4)
            if not hbuf:
                return self.error()

            ver, cmd, _, atyp = list(hbuf)
            if ver != 5 and cmd != 1:
                return self.error()

            if atyp == 1:
                dest = ".".join(str(i) for i in recv_exact(csock, 4))
            elif atyp == 3:
                n, = array.array("B", csock.recv(1))
                dest = recv_exact(csock, n).decode()
            elif atyp == 4:
                dest = ":".join(recv_exact(csock, 2).hex() for _ in range(8))
                return self.error()
            else:
                return self.error()

            port = int(recv_exact(csock, 2).hex(), 16)
            try:
                with self.create_socket(dest, port) as ssock:
                    SocksProxy(ssock, csock).run()
            except BrokenPipeError:
                E("======== Tor crashed, please restart! ========")
                exit()
        except Exception:
            E("Socket closed by exception")
            csock.close()
            self.client_sock = None

if __name__ == "__main__":
    register_logger(False)
    tor = TorClient()
    with tor.create_circuit() as circuit, SocksServer(circuit) as socks_serv:
        socks_serv.start()
