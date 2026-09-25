"""
Post-quantum migration of payments_service.encrypt_card_number.

Crypto-agility wrapper
----------------------
Set CARD_CRYPTO_BACKEND in the environment (or pass backend= explicitly):

  "rsa"    – legacy RSA-OAEP (keep working during rollout; DEPRECATED)
  "hybrid" – X25519 + ML-KEM-768 KEM, shared secrets combined with
             HKDF-SHA-256, encrypted with AES-256-GCM  ← DEFAULT

The hybrid scheme follows the pattern recommended in NIST SP 800-227 (draft)
and NIST IR 8547: combine a classical and a post-quantum KEM so that security
holds as long as *either* component is unbroken.

ML-KEM-768 backend
-------------------
We attempt to import liboqs-python (``import oqs``).  If it is not installed
(e.g. Python 3.14 not yet supported), _MlKem768 falls back to a clearly named
placeholder that raises NotImplementedError at call time.  Everything else —
X25519 key exchange, HKDF, AES-256-GCM — continues to work as a
"classical-only hybrid" until the ML-KEM leg is available.

TODO (ML-KEM plug-in point): install liboqs-python >= 0.10 and remove
_MlKem768Unavailable.  The real _MlKem768 class below shows the exact API.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# ML-KEM-768 backend (liboqs) — with graceful fallback
# ---------------------------------------------------------------------------

_OQS_AVAILABLE = False

try:
    import oqs  # type: ignore[import]

    class _MlKem768:
        """Real ML-KEM-768 via liboqs-python (FIPS 203)."""

        ALG = "Kyber768"  # liboqs name for ML-KEM-768

        @staticmethod
        def keypair() -> Tuple[bytes, bytes]:
            """Return (public_key_bytes, secret_key_bytes)."""
            with oqs.KeyEncapsulation(_MlKem768.ALG) as kem:
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()
            return pk, sk

        @staticmethod
        def encapsulate(public_key_bytes: bytes) -> Tuple[bytes, bytes]:
            """Return (ciphertext, shared_secret)."""
            with oqs.KeyEncapsulation(_MlKem768.ALG) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key_bytes)
            return ciphertext, shared_secret

        @staticmethod
        def decapsulate(secret_key_bytes: bytes, ciphertext: bytes) -> bytes:
            """Return shared_secret."""
            with oqs.KeyEncapsulation(_MlKem768.ALG, secret_key=secret_key_bytes) as kem:
                return kem.decap_secret(ciphertext)

    _OQS_AVAILABLE = True

except ModuleNotFoundError:

    class _MlKem768Unavailable:  # type: ignore[no-redef]
        """
        Placeholder — liboqs-python is not installed on this interpreter.

        TODO: replace with _MlKem768 once liboqs-python supports Python 3.14.
              Install: pip install liboqs-python
              Then remove this class and rename _MlKem768 to be the active one.
        """

        @staticmethod
        def keypair() -> Tuple[bytes, bytes]:
            raise NotImplementedError(
                "ML-KEM-768 requires liboqs-python. "
                "Run: pip install liboqs-python"
            )

        @staticmethod
        def encapsulate(public_key_bytes: bytes) -> Tuple[bytes, bytes]:
            raise NotImplementedError(
                "ML-KEM-768 requires liboqs-python. "
                "Run: pip install liboqs-python"
            )

        @staticmethod
        def decapsulate(secret_key_bytes: bytes, ciphertext: bytes) -> bytes:
            raise NotImplementedError(
                "ML-KEM-768 requires liboqs-python. "
                "Run: pip install liboqs-python"
            )

    _MlKem768 = _MlKem768Unavailable  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Wire format for hybrid ciphertext
# ---------------------------------------------------------------------------
# All fields are length-prefixed with a 2-byte big-endian uint16:
#   [2B x25519_pub_len][x25519_pub_bytes]
#   [2B mlkem_ct_len][mlkem_ct_bytes]   (0 bytes when ML-KEM unavailable)
#   [12B nonce][ciphertext_with_tag]
#
# The combined KDF input is:
#   HKDF-SHA256(ikm = x25519_ss || mlkem_ss, salt=None, info=b"hybrid-card-v1")


def _pack_u16(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def _unpack_u16(buf: bytes, offset: int) -> Tuple[bytes, int]:
    (length,) = struct.unpack_from(">H", buf, offset)
    start = offset + 2
    return buf[start : start + length], start + length


# ---------------------------------------------------------------------------
# Hybrid key type
# ---------------------------------------------------------------------------


@dataclass
class HybridPublicKey:
    """Holds the X25519 public key and (optionally) the ML-KEM-768 public key."""

    x25519: X25519PublicKey
    mlkem: bytes  # raw ML-KEM-768 public key; empty bytes when unavailable


@dataclass
class HybridPrivateKey:
    """Holds the X25519 private key and (optionally) the ML-KEM-768 secret key."""

    x25519: X25519PrivateKey
    mlkem_sk: bytes  # raw ML-KEM-768 secret key; empty bytes when unavailable
    mlkem_pk: bytes  # raw ML-KEM-768 public key; empty bytes when unavailable

    def public_key(self) -> HybridPublicKey:
        return HybridPublicKey(
            x25519=self.x25519.public_key(),
            mlkem=self.mlkem_pk,
        )


def generate_hybrid_keypair() -> HybridPrivateKey:
    """Generate a fresh X25519 + ML-KEM-768 hybrid key pair."""
    x25519_sk = X25519PrivateKey.generate()
    if _OQS_AVAILABLE:
        mlkem_pk, mlkem_sk = _MlKem768.keypair()
    else:
        mlkem_pk, mlkem_sk = b"", b""
    return HybridPrivateKey(x25519=x25519_sk, mlkem_sk=mlkem_sk, mlkem_pk=mlkem_pk)


# ---------------------------------------------------------------------------
# Hybrid encrypt / decrypt
# ---------------------------------------------------------------------------


def _hybrid_encrypt(plaintext: bytes, recipient_pub: HybridPublicKey) -> bytes:
    """Encrypt *plaintext* with X25519 + (optional) ML-KEM-768 + AES-256-GCM."""
    # --- X25519 leg ---
    eph_x25519_sk = X25519PrivateKey.generate()
    eph_x25519_pk_bytes = eph_x25519_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    x25519_ss = eph_x25519_sk.exchange(recipient_pub.x25519)

    # --- ML-KEM-768 leg ---
    if _OQS_AVAILABLE and recipient_pub.mlkem:
        mlkem_ct, mlkem_ss = _MlKem768.encapsulate(recipient_pub.mlkem)
    else:
        mlkem_ct, mlkem_ss = b"", b""

    # --- Combine shared secrets with HKDF-SHA-256 ---
    combined_ss = x25519_ss + mlkem_ss  # concatenate before KDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-card-v1",
    ).derive(combined_ss)

    # --- AES-256-GCM ---
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    # --- Wire format ---
    return (
        _pack_u16(eph_x25519_pk_bytes)
        + _pack_u16(mlkem_ct)
        + nonce
        + ciphertext
    )


def _hybrid_decrypt(ciphertext_blob: bytes, recipient_priv: HybridPrivateKey) -> bytes:
    """Decrypt a blob produced by _hybrid_encrypt."""
    offset = 0

    # --- X25519 leg ---
    eph_x25519_pk_bytes, offset = _unpack_u16(ciphertext_blob, offset)
    eph_x25519_pub = X25519PublicKey.from_public_bytes(eph_x25519_pk_bytes)
    x25519_ss = recipient_priv.x25519.exchange(eph_x25519_pub)

    # --- ML-KEM-768 leg ---
    mlkem_ct, offset = _unpack_u16(ciphertext_blob, offset)
    if _OQS_AVAILABLE and mlkem_ct:
        mlkem_ss = _MlKem768.decapsulate(recipient_priv.mlkem_sk, mlkem_ct)
    else:
        mlkem_ss = b""

    # --- Reconstruct AES-256-GCM key ---
    combined_ss = x25519_ss + mlkem_ss
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-card-v1",
    ).derive(combined_ss)

    # --- AES-256-GCM decrypt ---
    nonce = ciphertext_blob[offset : offset + 12]
    enc_data = ciphertext_blob[offset + 12 :]
    return AESGCM(aes_key).decrypt(nonce, enc_data, None)


# ---------------------------------------------------------------------------
# Crypto-agility wrapper  (public API)
# ---------------------------------------------------------------------------

_VALID_BACKENDS = ("hybrid", "rsa")


def encrypt_card_number(
    card_number: str,
    recipient_pub: HybridPublicKey,
    *,
    backend: str | None = None,
) -> bytes:
    """
    Encrypt *card_number* for *recipient_pub*.

    backend : "hybrid" (default) | "rsa" (legacy, deprecated)
    Override with the env var CARD_CRYPTO_BACKEND.
    """
    effective = (backend or os.environ.get("CARD_CRYPTO_BACKEND", "hybrid")).lower()
    if effective not in _VALID_BACKENDS:
        raise ValueError(f"Unknown backend {effective!r}. Choose from {_VALID_BACKENDS}")

    if effective == "rsa":
        # Legacy path — kept so existing encrypted blobs can still be produced
        # during a rolling deployment.  Remove once all clients are migrated.
        import warnings

        warnings.warn(
            "RSA backend is deprecated and quantum-vulnerable. "
            "Migrate to 'hybrid' (ML-KEM-768 + X25519).",
            DeprecationWarning,
            stacklevel=2,
        )
        from cryptography.hazmat.primitives.asymmetric import padding as _padding
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        if not isinstance(recipient_pub, RSAPublicKey):
            raise TypeError("RSA backend requires an RSAPublicKey, not HybridPublicKey")
        return recipient_pub.encrypt(
            card_number.encode(),
            _padding.OAEP(
                mgf=_padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    # Default: hybrid
    return _hybrid_encrypt(card_number.encode(), recipient_pub)


def decrypt_card_number(
    ciphertext: bytes,
    recipient_priv: HybridPrivateKey,
    *,
    backend: str | None = None,
) -> str:
    """
    Decrypt a blob produced by encrypt_card_number.

    backend must match whatever was used to encrypt.
    """
    effective = (backend or os.environ.get("CARD_CRYPTO_BACKEND", "hybrid")).lower()
    if effective == "rsa":
        from cryptography.hazmat.primitives.asymmetric import padding as _padding
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

        if not isinstance(recipient_priv, RSAPrivateKey):
            raise TypeError("RSA backend requires an RSAPrivateKey")
        plaintext = recipient_priv.decrypt(
            ciphertext,
            _padding.OAEP(
                mgf=_padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext.decode()

    return _hybrid_decrypt(ciphertext, recipient_priv).decode()
