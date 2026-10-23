"""Dual-stack lab listener on the ports given as arguments."""
import selectors
import socket
import sys

selector = selectors.DefaultSelector()
for port in map(int, sys.argv[1:]):
    for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((address, port))
        listener.listen(128)
        selector.register(listener, selectors.EVENT_READ)
print("ready", flush=True)
while True:
    for key, _ in selector.select():
        client, _ = key.fileobj.accept()
        with client:
            client.sendall(b"horizon-lab\n")
