"""TLS certificates and settings for the client-server connection.

Why TLS on top of the end-to-end encryption?
    End-to-end encryption already protects message *contents*. TLS protects
    everything else on the wire: the login hash (which would otherwise be
    replayable), usernames, the user list, who sends to whom, and the
    message envelopes. It also proves to the client that it is talking to
    the real server and not an impostor in the middle.

How trust works here (a private certificate authority):

    ca.crt       "Secure Chat local CA": the ONLY certificate clients trust.
                 Copy this file to every client computer.
    server.crt   the server's certificate, signed by the CA, valid for the
                 server's host names / IP addresses.
    server.key   the server's private key. Never leaves the server.

The CA's own private key is used once, to sign server.crt, and then thrown
away, so nobody (including a thief of the server folder) can mint another
certificate that clients would trust. To change host names, delete the tls
folder; a new CA is made and ca.crt must be copied to clients again.

TLS itself is Python's standard `ssl` module (OpenSSL). Certificates are
built with `cryptography`. Nothing here is hand-made cryptography.
"""

import datetime
import ipaddress
import os
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_FILE, CERT_FILE, KEY_FILE = "ca.crt", "server.crt", "server.key"
DEFAULT_HOSTNAMES = ("localhost", "127.0.0.1", "::1")


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _san_entries(hostnames):
    entries = []
    for h in dict.fromkeys(hostnames):  # de-duplicate, keep order
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            entries.append(x509.DNSName(h))
    return entries


def generate_server_tls(folder: str, hostnames=DEFAULT_HOSTNAMES) -> dict:
    """Create ca.crt, server.crt and server.key in `folder`. Returns their paths."""
    os.makedirs(folder, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(minutes=5)  # tolerate small clock differences

    # 1. The certificate authority (P-256 elliptic-curve key: fast and strong).
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Secure Chat local CA"))
        .issuer_name(_name("Secure Chat local CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                     crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # 2. The server's own key and certificate, signed by the CA.
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Secure Chat server"))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(_san_entries(hostnames)), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    del ca_key  # never saved: no one can issue more trusted certificates

    paths = tls_paths(folder)
    _write(paths["ca"], ca_cert.public_bytes(serialization.Encoding.PEM))
    _write(paths["cert"], server_cert.public_bytes(serialization.Encoding.PEM))
    _write(paths["key"], server_key.private_bytes(serialization.Encoding.PEM,
                                                  serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
    return paths


def tls_paths(folder: str) -> dict:
    return {"ca": os.path.join(folder, CA_FILE), "cert": os.path.join(folder, CERT_FILE),
            "key": os.path.join(folder, KEY_FILE)}


def ensure_server_tls(folder: str, hostnames=DEFAULT_HOSTNAMES) -> tuple[dict, bool]:
    """Use the existing certificates in `folder`, or create them. Returns (paths, created)."""
    paths = tls_paths(folder)
    if all(os.path.exists(p) for p in paths.values()):
        return paths, False
    return generate_server_tls(folder, hostnames), True


def certificate_fingerprint(pem_path: str) -> str:
    """SHA-256 fingerprint of a certificate, for checking ca.crt was copied correctly."""
    with open(pem_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    hexed = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(hexed[i:i + 2] for i in range(0, 24, 2)) + ":..."


def server_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    """TLS 1.3 only. TLS 1.3 always uses forward-secret key exchange and
    authenticated encryption (AES-GCM or ChaCha20-Poly1305)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


def client_context(ca_path: str) -> ssl.SSLContext:
    """Trust ONLY our CA (not the computer's usual list of public CAs),
    require TLS 1.3, and check the certificate matches the host name."""
    ctx = ssl.create_default_context(cafile=ca_path)  # verify_mode=CERT_REQUIRED, check_hostname=True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
