"""Independent OPC UA discovery target for nyxr interoperability checks.

Runs an asyncua (FreeOpcUa) server with a SecurityPolicy None endpoint and a
Basic256Sha256 SignAndEncrypt endpoint backed by a throwaway self-signed
certificate. It is a local lab responder, never a device.

    python opcua_server.py [port]
"""

import asyncio
import datetime
import sys
import tempfile
from pathlib import Path

from asyncua import Server, ua
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

APP_URI = "urn:nyxr:lab:opcua"


def write_certificate(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nyxr lab OPC UA server")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(APP_URI)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "server.der", directory / "server.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    )
    return cert_path, key_path


async def main(port: int) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cert_path, key_path = write_certificate(Path(tmp))
        server = Server()
        await server.init()
        server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
        server.set_server_name("nyxr lab OPC UA server")
        await server.set_application_uri(APP_URI)
        server.set_security_policy(
            [ua.SecurityPolicyType.NoSecurity, ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt]
        )
        await server.load_certificate(str(cert_path))
        await server.load_private_key(str(key_path))
        async with server:
            print("ready", flush=True)
            while True:
                await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 48400))
