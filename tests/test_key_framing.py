"""Key-framing interop tests (wave 2026-08-16-key-framing-interop, F2).

Covers AC-2.1..AC-2.6 for hermes_mesh.auth.verify_ed25519's two-path split:
PEM-marked input is STRICT PEM (no raw fallback); raw base64 SPKI input is
stripped (YAML block scalars carry trailing newlines), strict base64-decoded,
length-guarded to exactly 44 bytes (Ed25519 SPKI DER), and must parse to an
Ed25519PublicKey — X25519 SPKI is also 44 bytes (OID 2B 65 6E vs Ed25519
2B 65 70) and is rejected by the isinstance check.
"""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from hermes_mesh import auth as mesh_auth


def _ed25519_fixture():
    """Return (raw_spki_b64, private_pem, public_pem) for a fresh Ed25519 pair."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    der = public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert len(der) == 44  # Ed25519 SPKI DER shape
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return base64.b64encode(der).decode("ascii"), private_pem, public_pem


class TestEd25519KeyFraming:
    """AC-2.1..AC-2.4, AC-2.6 — raw base64 SPKI tolerance + strict-PEM guard."""

    def test_raw_base64_spki_verifies(self):
        """AC-2.1: raw base64 SPKI public key verifies (pilot's original case)."""
        raw_b64, private_pem, _ = _ed25519_fixture()
        message = b"hello mesh"
        sig = mesh_auth.sign_ed25519(private_pem, message)
        assert mesh_auth.verify_ed25519(raw_b64, message, sig) is True

    def test_pem_entry_unchanged(self):
        """AC-2.2: PEM public key still verifies (regression)."""
        _, private_pem, public_pem = _ed25519_fixture()
        message = b"hello mesh"
        sig = mesh_auth.sign_ed25519(private_pem, message)
        assert mesh_auth.verify_ed25519(public_pem, message, sig) is True

    def test_garbage_base64_false(self):
        """AC-2.3: garbage base64 (decodes to 9 bytes, not SPKI) -> False."""
        assert mesh_auth.verify_ed25519("bm90LWEta2V5", b"x", "c2ln") is False

    def test_32_byte_seed_rejected(self):
        """AC-2.4: base64 of 32 zero bytes is not a 44-byte SPKI -> False."""
        seed_b64 = base64.b64encode(b"\x00" * 32).decode("ascii")
        assert mesh_auth.verify_ed25519(seed_b64, b"x", "c2ln") is False

    def test_raw_with_trailing_newline_verifies(self):
        """AC-2.6: YAML block scalars carry a trailing newline; strip handles it."""
        raw_b64, private_pem, _ = _ed25519_fixture()
        message = b"hello mesh"
        sig = mesh_auth.sign_ed25519(private_pem, message)
        assert mesh_auth.verify_ed25519(raw_b64 + "\n", message, sig) is True

    def test_corrupt_pem_false_no_raw_fallback(self):
        """AC-2.6: PEM-marked corrupt input -> False, NEVER raw-reinterpreted."""
        corrupt = "-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----"
        assert mesh_auth.verify_ed25519(corrupt, b"x", "c2ln") is False
        # Same with a trailing newline: a (wrong) raw fallback would strip then
        # base64-decode the PEM text, which is not valid base64 -> also False.
        # Pin that the function returns False rather than raising or verifying.
        assert mesh_auth.verify_ed25519(corrupt + "\n", b"x", "c2ln") is False


class TestX25519RejectedByIsInstance:
    """AC-2.5 — X25519 SPKI is 44 bytes too; only the isinstance check rejects it.

    MUTATION PROOF: comment out the
        if not isinstance(public, Ed25519PublicKey):
            return False
    lines in hermes_mesh/auth.py -> this test FAILS.

    The whole function body is wrapped (no exception escapes), so a black-box
    "result is False" assertion would still pass under mutation (X25519PublicKey
    has no .verify -> AttributeError is swallowed). This test therefore pins the
    MECHANISM: load_der_public_key must never reach .verify on an X25519 key.
    """

    def test_x25519_verify_never_reached(self, monkeypatch):
        x_priv = X25519PrivateKey.generate()
        der = x_priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert len(der) == 44  # X25519 SPKI shares the Ed25519 length guard
        raw_b64 = base64.b64encode(der).decode("ascii")

        real_load_der = serialization.load_der_public_key
        verify_calls = []

        class _Probe:
            """Records a fall-through to verify; mimics X25519PublicKey's absence
            of a verify method by raising TypeError."""

            def verify(self, signature, message):
                verify_calls.append((signature, message))
                raise TypeError(
                    "X25519PublicKey has no verify() — isinstance guard skipped"
                )

        def _probe_load_der(data):
            key = real_load_der(data)
            if isinstance(key, X25519PublicKey):
                return _Probe()
            return key

        monkeypatch.setattr(serialization, "load_der_public_key", _probe_load_der)

        result = mesh_auth.verify_ed25519(raw_b64, b"message", "c2ln")
        assert result is False
        assert verify_calls == []  # MUTATION: removing the isinstance line appends here
