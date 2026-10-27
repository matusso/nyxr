"""Independent S7comm target for nyxr interoperability checks.

Runs the python-snap7 server, which answers Setup Communication and the SZL
identity lists with its own canned CPU data. It is a local lab responder,
never a device.

    python s7_server.py [port]
"""

import sys
import time

from snap7.server import Server


def main(port: int) -> None:
    server = Server()
    server.start(tcp_port=port)
    print("ready", flush=True)
    try:
        while True:
            time.sleep(1)
    finally:
        server.stop()
        server.destroy()


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 1102)
