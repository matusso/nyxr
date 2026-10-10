"""Dual-stack lab listener. An optional backend makes this a TCP proxy."""
import selectors
import socket
import sys

selector = selectors.DefaultSelector()
for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind((address, 443))
    listener.listen(128)
    selector.register(listener, selectors.EVENT_READ)
print("ready", flush=True)
while True:
    for key, _ in selector.select():
        client, peer = key.fileobj.accept()
        with client:
            try:
                if len(sys.argv) > 1:
                    # The lab readiness handshake exercises forwarding. HZ-001
                    # sends only SYNs and measures the frontend's TCP stack.
                    with socket.create_connection((sys.argv[1], 443), timeout=1) as backend:
                        client.sendall(backend.recv(128))
                else:
                    client.sendall(b"horizon-lab\n")
                print("connection", peer, flush=True)
            except OSError as error:
                print("connection-error", error, flush=True)
