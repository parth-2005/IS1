import socket



def send_bytes(sock: socket.socket, data: bytes) -> None:
    """Send a 4-byte length prefix followed by data."""
    length = len(data)
    sock.sendall(length.to_bytes(4, "big") + data)

"""Thin CLI wrapper that imports the refactored MessagingService from the messaging package.

This keeps the project root clean and routes logic into `messaging/protocol.py`.
"""

from messaging import MessagingService


def main():
    mode = input("Enter mode (server/client): ").lower()
    host = input("Enter host IP (default: 127.0.0.1): ") or "127.0.0.1"
    port = int(input("Enter port (default: 5555): ") or 5555)

    service = MessagingService(host, port)
    service.start(mode)


if __name__ == "__main__":
    main()