"""Self-signed test certificates in the form the OPNsense keeps them in config.xml (<cert><crt>base64 PEM</crt>)."""
import base64
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_cert_b64(common_name, valid_days=365, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode("ascii")


def cert_xml(refid, common_name, valid_days=365):
    return (f"<cert><refid>{refid}</refid><descr>{common_name}</descr>"
            f"<crt>{make_cert_b64(common_name, valid_days)}</crt></cert>")
