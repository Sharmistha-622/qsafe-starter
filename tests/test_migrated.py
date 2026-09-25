"""Round-trip tests for migrated/payments_service_pqc.py."""
from __future__ import annotations

import warnings

import pytest

from migrated.payments_service_pqc import (
    _OQS_AVAILABLE,
    HybridPrivateKey,
    decrypt_card_number,
    encrypt_card_number,
    generate_hybrid_keypair,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_CARD = "4111111111111111"


def _fresh_keypair() -> HybridPrivateKey:
    return generate_hybrid_keypair()


# ---------------------------------------------------------------------------
# Hybrid backend (default)
# ---------------------------------------------------------------------------


class TestHybridRoundTrip:
    def test_encrypt_returns_bytes(self) -> None:
        """encrypt_card_number must return bytes."""
        priv = _fresh_keypair()
        ct = encrypt_card_number(SAMPLE_CARD, priv.public_key())
        assert isinstance(ct, bytes)

    def test_decrypt_recovers_plaintext(self) -> None:
        """Decrypting the hybrid ciphertext must return the original card number."""
        priv = _fresh_keypair()
        ct = encrypt_card_number(SAMPLE_CARD, priv.public_key())
        recovered = decrypt_card_number(ct, priv)
        assert recovered == SAMPLE_CARD

    def test_different_cards_produce_different_ciphertexts(self) -> None:
        """Two different card numbers must produce different ciphertexts."""
        priv = _fresh_keypair()
        pub = priv.public_key()
        ct1 = encrypt_card_number("4111111111111111", pub)
        ct2 = encrypt_card_number("5500000000000004", pub)
        assert ct1 != ct2

    def test_same_card_produces_different_ciphertexts(self) -> None:
        """Same plaintext must produce different ciphertexts (fresh nonce each time)."""
        priv = _fresh_keypair()
        pub = priv.public_key()
        ct1 = encrypt_card_number(SAMPLE_CARD, pub)
        ct2 = encrypt_card_number(SAMPLE_CARD, pub)
        assert ct1 != ct2

    def test_wrong_key_cannot_decrypt(self) -> None:
        """Decryption with a different private key must raise an exception."""
        priv1 = _fresh_keypair()
        priv2 = _fresh_keypair()
        ct = encrypt_card_number(SAMPLE_CARD, priv1.public_key())
        with pytest.raises(Exception):
            decrypt_card_number(ct, priv2)

    def test_tampered_ciphertext_raises(self) -> None:
        """AES-256-GCM authentication must reject a tampered ciphertext."""
        priv = _fresh_keypair()
        ct = bytearray(encrypt_card_number(SAMPLE_CARD, priv.public_key()))
        ct[-1] ^= 0xFF  # flip last byte of AEAD tag
        with pytest.raises(Exception):
            decrypt_card_number(bytes(ct), priv)

    def test_explicit_hybrid_backend_kwarg(self) -> None:
        """Passing backend='hybrid' explicitly must round-trip correctly."""
        priv = _fresh_keypair()
        pub = priv.public_key()
        ct = encrypt_card_number(SAMPLE_CARD, pub, backend="hybrid")
        recovered = decrypt_card_number(ct, priv, backend="hybrid")
        assert recovered == SAMPLE_CARD

    def test_env_var_selects_hybrid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CARD_CRYPTO_BACKEND=hybrid must use the hybrid path."""
        monkeypatch.setenv("CARD_CRYPTO_BACKEND", "hybrid")
        priv = _fresh_keypair()
        ct = encrypt_card_number(SAMPLE_CARD, priv.public_key())
        assert decrypt_card_number(ct, priv) == SAMPLE_CARD

    def test_invalid_backend_raises(self) -> None:
        """An unknown backend name must raise ValueError."""
        priv = _fresh_keypair()
        with pytest.raises(ValueError, match="Unknown backend"):
            encrypt_card_number(SAMPLE_CARD, priv.public_key(), backend="quantum-magic")


# ---------------------------------------------------------------------------
# Legacy RSA backend (crypto-agility: must still work)
# ---------------------------------------------------------------------------


class TestRsaLegacyBackend:
    def test_rsa_roundtrip(self) -> None:
        """Legacy RSA backend must encrypt and decrypt correctly."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pub = rsa_priv.public_key()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ct = encrypt_card_number(SAMPLE_CARD, rsa_pub, backend="rsa")
            recovered = decrypt_card_number(ct, rsa_priv, backend="rsa")

        assert recovered == SAMPLE_CARD

    def test_rsa_backend_emits_deprecation_warning(self) -> None:
        """RSA backend must emit a DeprecationWarning."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.warns(DeprecationWarning, match="quantum-vulnerable"):
            encrypt_card_number(SAMPLE_CARD, rsa_priv.public_key(), backend="rsa")

    def test_env_var_selects_rsa(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CARD_CRYPTO_BACKEND=rsa must route through the legacy path."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        monkeypatch.setenv("CARD_CRYPTO_BACKEND", "rsa")
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pub = rsa_priv.public_key()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ct = encrypt_card_number(SAMPLE_CARD, rsa_pub)
            recovered = decrypt_card_number(ct, rsa_priv)

        assert recovered == SAMPLE_CARD


# ---------------------------------------------------------------------------
# ML-KEM availability flag
# ---------------------------------------------------------------------------


class TestMlKemFlag:
    def test_oqs_flag_is_bool(self) -> None:
        """_OQS_AVAILABLE must be a bool."""
        assert isinstance(_OQS_AVAILABLE, bool)

    @pytest.mark.skipif(_OQS_AVAILABLE, reason="oqs is available — placeholder not active")
    def test_placeholder_raises_not_implemented(self) -> None:
        """When oqs is absent, _MlKem768 methods must raise NotImplementedError."""
        from migrated.payments_service_pqc import _MlKem768

        with pytest.raises(NotImplementedError):
            _MlKem768.keypair()
        with pytest.raises(NotImplementedError):
            _MlKem768.encapsulate(b"fake-key")
        with pytest.raises(NotImplementedError):
            _MlKem768.decapsulate(b"fake-sk", b"fake-ct")

    @pytest.mark.skipif(not _OQS_AVAILABLE, reason="oqs not installed")
    def test_mlkem_roundtrip_when_available(self) -> None:
        """When liboqs is installed, the full ML-KEM-768 leg must round-trip."""
        priv = _fresh_keypair()
        pub = priv.public_key()
        assert pub.mlkem != b"", "ML-KEM public key should be non-empty"
        ct = encrypt_card_number(SAMPLE_CARD, pub, backend="hybrid")
        recovered = decrypt_card_number(ct, priv, backend="hybrid")
        assert recovered == SAMPLE_CARD
