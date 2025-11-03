import socket
import threading
from typing import Optional

# Use the project's educational crypto implementation (do not modify it)
from infoSec.Crypto import generate_keypair, generate_aes_key, aes_encrypt, aes_decrypt


def send_bytes(sock: socket.socket, data: bytes) -> None:
    length = len(data)
    sock.sendall(length.to_bytes(4, "big") + data)


def recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> Optional[bytes]:
    header = recv_exact(sock, 4)
    if not header:
        return None
    length = int.from_bytes(header, "big")
    return recv_exact(sock, length)


def recv_line(sock: socket.socket) -> Optional[bytes]:
    data = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            return None
        data += ch
        if ch == b"\n":
            break
    return data.rstrip(b"\n")


class MessagingService:
    """Server/client messaging using the project's educational RSA for wrapping an AES key and AES(CBC) for payloads.

    This class contains the refactored networking and handshake logic originally in `app.py`.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 5555):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start_server(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        print(f"Server listening on {self.host}:{self.port}")

        while True:
            client, address = self.socket.accept()
            print(f"Connected with {address}")
            t = threading.Thread(target=self.handle_client, args=(client,))
            t.start()

    def handle_client(self, client: socket.socket):
        try:
            public_key, private_key = generate_keypair()  # (e,n), (d,n)
            e, n = public_key
            d, _ = private_key

            handshake = f"{e},{n}\n".encode()
            client.sendall(handshake)

            line = recv_line(client)
            if not line:
                print("Client closed during handshake")
                return
            parts = line.decode().split(":", 1)
            if len(parts) != 2:
                print("Invalid wrapped key format")
                return
            key_len = int(parts[0])
            c_hex = parts[1]
            c_bytes = bytes.fromhex(c_hex)
            c_int = int.from_bytes(c_bytes, "big")

            m_int = pow(c_int, d, n)
            aes_key = m_int.to_bytes(key_len, "big")
            print(f"Derived AES key ({len(aes_key)} bytes) for client")

            while True:
                frame = recv_frame(client)
                if frame is None:
                    break
                try:
                    plaintext = aes_decrypt(frame, aes_key)
                    print(f"Client: {plaintext}")
                except Exception as exc:
                    print(f"Failed to decrypt message: {exc}")
                    break
        finally:
            client.close()

    def connect_to_server(self) -> bool:
        try:
            self.socket.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def start_client_loop(self):
        line = recv_line(self.socket)
        if not line:
            print("Server closed during handshake")
            return
        e_str, n_str = line.decode().split(",")
        e = int(e_str)
        n = int(n_str)

        n_bytes = (n.bit_length() + 7) // 8
        key_len = max(1, min(16, n_bytes - 1)) if n_bytes > 1 else 1
        aes_key = generate_aes_key(key_len)

        m_int = int.from_bytes(aes_key, "big")
        c_int = pow(m_int, e, n)
        c_bytes = c_int.to_bytes(n_bytes, "big")

        msg = f"{key_len}:{c_bytes.hex()}\n".encode()
        self.socket.sendall(msg)
        print(f"Sent wrapped AES key ({key_len} bytes)")

        def recv_thread():
            try:
                while True:
                    frame = recv_frame(self.socket)
                    if frame is None:
                        break
                    try:
                        txt = aes_decrypt(frame, aes_key)
                        print(f"\nServer: {txt}\n", end="")
                    except Exception as exc:
                        print(f"Failed to decrypt server message: {exc}")
                        break
            finally:
                self.socket.close()

        rt = threading.Thread(target=recv_thread, daemon=True)
        rt.start()

        try:
            while True:
                message = input("Enter message (or 'quit' to exit): ")
                if message.lower() == "quit":
                    break
                ct = aes_encrypt(message, aes_key)
                send_bytes(self.socket, ct)
        finally:
            self.socket.close()

    def start(self, mode: str = "server"):
        if mode == "server":
            t = threading.Thread(target=self.start_server, daemon=True)
            t.start()
            try:
                while True:
                    t.join(1)
            except KeyboardInterrupt:
                print("Shutting down server")
        else:
            if self.connect_to_server():
                self.start_client_loop()
