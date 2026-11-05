"""Signing keys for gateway access tokens.

HMAC secrets sign and verify with the same value. RS*, ES*, and PS* tokens
are signed with the private key and verified with the derived public key.
The private key is never written into tokens, JWKS, logs, or errors.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import jwt as pyjwt

from ..config import (
    get_oauth_algorithm,
    get_oauth_signing_key,
    get_oauth_signing_key_file,
)

_HMAC_ALGS = {"HS256", "HS384", "HS512"}
_RSA_ALGS = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
_EC_CURVES = {"ES256": "secp256r1", "ES384": "secp384r1", "ES512": "secp521r1"}
_EC_CRV = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
_MIN_HMAC_BYTES = 32


class SigningConfigError(RuntimeError):
    """The signing algorithm or key cannot be used. The message has no key material."""


@dataclass(frozen=True)
class _LoadedKey:
    algorithm: str
    hmac_secret: str | None = None
    private_key: object | None = None
    jwk: dict | None = None

    def __repr__(self) -> str:
        kind = "hmac" if self.hmac_secret is not None else "asymmetric"
        return f"_LoadedKey(algorithm={self.algorithm!r}, kind={kind})"


def jwk_thumbprint(members: dict[str, str]) -> str:
    """RFC 7638 SHA-256 JWK thumbprint (base64url, no padding)."""
    encoded = json.dumps(members, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64url(hashlib.sha256(encoded).digest())


def validate_signing_config() -> None:
    """Fail fast when the process cannot safely sign tokens."""
    _load()


def encode_jwt(payload: dict) -> str:
    """Sign ``payload``. Asymmetric tokens carry a ``kid`` thumbprint header."""
    loaded = _load()
    if loaded.hmac_secret is not None:
        token = pyjwt.encode(payload, loaded.hmac_secret, algorithm=loaded.algorithm)
    else:
        token = pyjwt.encode(
            payload,
            loaded.private_key,
            algorithm=loaded.algorithm,
            headers={"kid": loaded.jwk["kid"]},
        )
    if isinstance(token, bytes):
        return token.decode("ascii")
    return token


def decode_jwt(token: str, *, audience: str) -> dict:
    """Verify a gateway token. Asymmetric algorithms use the public key."""
    loaded = _load()
    if loaded.hmac_secret is not None:
        key: object = loaded.hmac_secret
    else:
        key = loaded.private_key.public_key()
    return pyjwt.decode(
        token,
        key,
        algorithms=[loaded.algorithm],
        audience=audience,
    )


def jwks_document() -> dict | None:
    """Public JWK set, or None when the algorithm is HMAC."""
    loaded = _load()
    if loaded.jwk is None:
        return None
    return {"keys": [loaded.jwk]}


def _load() -> _LoadedKey:
    algorithm = _canonical_algorithm(get_oauth_algorithm())
    if algorithm in _HMAC_ALGS:
        secret = _hmac_secret()
        if len(secret.encode("utf-8")) < _MIN_HMAC_BYTES:
            raise SigningConfigError(
                f"HMAC signing key for {algorithm} must be at least {_MIN_HMAC_BYTES} bytes"
            )
        return _LoadedKey(algorithm=algorithm, hmac_secret=secret)

    private_key = _load_private_key(_asymmetric_pem())
    _assert_key_matches(algorithm, private_key)
    return _LoadedKey(
        algorithm=algorithm,
        private_key=private_key,
        jwk=_public_jwk(private_key, algorithm),
    )


def _canonical_algorithm(raw: str) -> str:
    algorithm = raw.strip()
    if algorithm.lower() == "none":
        raise SigningConfigError("OAUTH_ALGORITHM 'none' is not permitted")
    if not algorithm or len(algorithm) > 16 or not algorithm.isalnum():
        raise SigningConfigError("OAUTH_ALGORITHM is not a supported algorithm")
    canonical = algorithm.upper()
    if canonical in _HMAC_ALGS or canonical in _RSA_ALGS or canonical in _EC_CURVES:
        return canonical
    raise SigningConfigError(f"Unsupported OAUTH_ALGORITHM '{canonical}'")


def _hmac_secret() -> str:
    path = get_oauth_signing_key_file()
    if path:
        try:
            raw = Path(path).read_bytes()
        except OSError:
            raise SigningConfigError("OAUTH_SIGNING_KEY_FILE could not be read") from None
        try:
            return raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise SigningConfigError("OAUTH_SIGNING_KEY_FILE is not a text HMAC secret") from None
    return get_oauth_signing_key()


def _asymmetric_pem() -> bytes:
    """PEM bytes. ``OAUTH_SIGNING_KEY_FILE`` wins over ``OAUTH_SIGNING_KEY``."""
    path = get_oauth_signing_key_file()
    if path:
        try:
            return Path(path).read_bytes()
        except OSError:
            raise SigningConfigError("OAUTH_SIGNING_KEY_FILE could not be read") from None
    return _pem_bytes(get_oauth_signing_key())


def _pem_bytes(value: str) -> bytes:
    if "\\n" in value and "-----BEGIN" in value:
        value = value.replace("\\n", "\n")
    if "-----BEGIN" in value and not value.endswith("\n"):
        value += "\n"
    return value.encode("utf-8")


def _load_private_key(pem: bytes) -> object:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        return load_pem_private_key(pem, password=None)
    except Exception:
        raise SigningConfigError(
            "OAuth signing key is not an unencrypted private key"
        ) from None


def _assert_key_matches(algorithm: str, key: object) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if algorithm in _RSA_ALGS:
        if not isinstance(key, rsa.RSAPrivateKey):
            raise SigningConfigError(f"{algorithm} requires an RSA private key")
        return
    curve = _EC_CURVES[algorithm]
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != curve:
        raise SigningConfigError(f"{algorithm} requires an EC private key on {curve}")


def _public_jwk(private_key: object, algorithm: str) -> dict:
    public_key = private_key.public_key()
    if algorithm in _RSA_ALGS:
        numbers = public_key.public_numbers()
        n = _b64url_uint(numbers.n)
        e = _b64url_uint(numbers.e)
        thumb = {"e": e, "kty": "RSA", "n": n}
        return {
            "kty": "RSA",
            "n": n,
            "e": e,
            "kid": jwk_thumbprint(thumb),
            "alg": algorithm,
            "use": "sig",
        }

    numbers = public_key.public_numbers()
    crv = _EC_CRV[public_key.curve.name]
    size = (public_key.curve.key_size + 7) // 8
    x = _b64url(numbers.x.to_bytes(size, "big"))
    y = _b64url(numbers.y.to_bytes(size, "big"))
    thumb = {"crv": crv, "kty": "EC", "x": x, "y": y}
    return {
        "kty": "EC",
        "crv": crv,
        "x": x,
        "y": y,
        "kid": jwk_thumbprint(thumb),
        "alg": algorithm,
        "use": "sig",
    }


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_uint(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return _b64url(value.to_bytes(length, "big"))
