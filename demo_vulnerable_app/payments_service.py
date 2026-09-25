"""DEMO ONLY - intentionally quantum-vulnerable code for the QSafe Scanner demo."""
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes


def create_customer_keys():
    # Long-lived customer encryption key: harvest-now-decrypt-later risk
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def encrypt_card_number(public_key, card_number: str) -> bytes:
    return public_key.encrypt(
        card_number.encode(),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def sign_transaction(payload: bytes) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.sign(payload, ec.ECDSA(hashes.SHA256()))


def legacy_checksum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()
