"""JWE envelope sign/verify using wallet DID keys (Askar backend).

Each token is RFC 7516 compact serialization: header.encrypted_key.iv.ciphertext.tag
Algorithm: ECDH-ES+A256KW with A256GCM content encryption.
Keys: Ed25519 DID keys are converted to X25519 for key agreement.

Sign flow (issuer):
  - Accepts one or more recipient DIDs.
  - Produces one independent compact JWE per DID (separate CEK, separate ephemeral key).
  - Returns a dict mapping each DID to its compact token.
  - The issuer sends each holder their own token.

Verify/decrypt flow (holder):
  - Accepts one compact JWE string.
  - Reads kid from protected header to identify the recipient DID.
  - Looks up that DID in the local wallet, fetches private key, decrypts.
"""

import base64
import json
from collections import OrderedDict
from typing import Any, Dict, List, Mapping, Tuple

from aries_askar import AskarError, Key, KeyAlg, ecdh

from ..core.profile import Profile
from ..messaging.jsonld.error import BadJWSHeaderError
from ..resolver.did_resolver import DIDResolver
from .base import BaseWallet
from .error import WalletError, WalletNotFoundError
from .jwt import did_lookup_name, nym_to_did
from .util import b64_to_bytes, bytes_to_b64

JWE_ALG = "ECDH-ES+A256KW"
JWE_ENC = "A256GCM"


def _b64url(data: bytes) -> str:
    return bytes_to_b64(data, urlsafe=True, pad=False)


def _from_b64url(data: str) -> bytes:
    return b64_to_bytes(data, urlsafe=True)


# ── Public-key extraction from a DID document ────────────────────────────────

def _pub_key_from_base58(vm: dict) -> bytes:
    from base58 import b58decode
    return b58decode(vm["publicKeyBase58"])


def _pub_key_from_multibase(vm: dict):
    from base58 import b58decode
    mb = vm["publicKeyMultibase"]
    if not mb.startswith("z"):
        return None
    raw = b58decode(mb[1:])
    if len(raw) > 2 and raw[0] == 0xED and raw[1] == 0x01:
        return raw[2:]
    return None


def _pub_key_from_jwk(vm: dict):
    jwk_data = vm["publicKeyJwk"]
    if jwk_data.get("kty") != "OKP" or jwk_data.get("crv") != "Ed25519":
        return None
    x = jwk_data.get("x", "")
    padded = x + "=" * (-len(x) % 4)
    return base64.urlsafe_b64decode(padded)


def _extract_ed25519_pub_bytes(vm: dict):
    """Return Ed25519 public key bytes from a verificationMethod dict, or None."""
    if "publicKeyBase58" in vm:
        return _pub_key_from_base58(vm)
    if "publicKeyMultibase" in vm:
        return _pub_key_from_multibase(vm)
    if "publicKeyJwk" in vm:
        return _pub_key_from_jwk(vm)
    return None


async def _resolve_recipient_public_key(profile: Profile, did: str) -> bytes:
    """Resolve a DID and return its Ed25519 public key as raw bytes."""
    resolver = profile.inject(DIDResolver)
    try:
        did_doc = await resolver.resolve(profile, did)
    except Exception as err:
        raise WalletNotFoundError(f"Failed to resolve DID '{did}': {err}") from err

    vms = did_doc.get("verificationMethod", [])
    if not vms:
        raise WalletError(f"No verificationMethod in DID document for '{did}'")

    for vm in vms:
        if not isinstance(vm, dict):
            continue
        key_bytes = _extract_ed25519_pub_bytes(vm)
        if key_bytes:
            return key_bytes

    raise WalletError(
        f"No supported Ed25519 public key found in DID document for '{did}'"
    )


# ── Sign (encrypt) ────────────────────────────────────────────────────────────

def _compact_jwe_for_recipient(
    payload_bytes: bytes,
    x25519_pub: Key,
    kid: str,
) -> str:
    """Build one compact JWE string for a single recipient public key.

    The full header (alg + enc + kid + epk) is used as AAD for encryption so
    that jwe_verify — which reads the header from the token's first part — uses
    the identical bytes as AAD during decryption.
    """
    try:
        epk = Key.generate(KeyAlg.X25519, ephemeral=True)
        cek = Key.generate(KeyAlg.A256GCM)
        wrapped = ecdh.EcdhEs(JWE_ALG, None, None).sender_wrap_key(
            KeyAlg.A256KW, epk, x25519_pub, cek
        )
    except AskarError as err:
        raise WalletError(f"Failed to wrap CEK for DID '{kid}'") from err

    epk_pub = json.loads(epk.get_jwk_public())
    header = OrderedDict([
        ("alg", JWE_ALG),
        ("enc", JWE_ENC),
        ("kid", kid),
        ("epk", epk_pub),
    ])
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())

    try:
        # AAD = the token's first part (header_b64) — must match jwe_verify
        encrypted = cek.aead_encrypt(payload_bytes, aad=header_b64.encode())
    except AskarError as err:
        raise WalletError("Failed to encrypt payload") from err

    return ".".join([
        header_b64,
        _b64url(wrapped.ciphertext),
        _b64url(encrypted.nonce),
        _b64url(encrypted.ciphertext),
        _b64url(encrypted.tag),
    ])


async def jwe_sign(
    profile: Profile,
    payload: Mapping[str, Any],
    recipient_dids: List[str],
) -> Dict[str, str]:
    """Encrypt payload for one or more recipient DIDs.

    Produces one independent compact JWE per DID (separate CEK + ephemeral key each).
    Returns a dict mapping each resolved DID to its compact JWE token string.

    The issuer sends each holder their own token. Holders verify with jwe_verify.

    Args:
        profile: The agent profile (issuer's profile).
        payload: A JSON-serializable dict to encrypt.
        recipient_dids: One or more holder DIDs. Resolved via DID resolver — they
                        do not need to be in the local wallet.

    Returns:
        Dict of {did: compact_jwe_string} — one entry per recipient DID.
    """
    if not recipient_dids:
        raise ValueError("At least one recipientDid is required")

    payload_bytes = json.dumps(payload).encode("utf-8")
    tokens: Dict[str, str] = {}

    for raw_did in recipient_dids:
        did = nym_to_did(raw_did)
        ed25519_pub_bytes = await _resolve_recipient_public_key(profile, did)

        try:
            ed_pub_key = Key.from_public_bytes(KeyAlg.ED25519, ed25519_pub_bytes)
            x25519_pub = ed_pub_key.convert_key(KeyAlg.X25519)
        except AskarError as err:
            raise WalletError(
                f"Failed to derive X25519 public key for DID '{did}'"
            ) from err

        tokens[did] = _compact_jwe_for_recipient(payload_bytes, x25519_pub, did)

    return tokens


# ── Verify (decrypt) ──────────────────────────────────────────────────────────

async def jwe_verify(profile: Profile, jwe_compact: str) -> Tuple[dict, str]:
    """Decrypt a compact JWE token using the wallet's own private key.

    Reads kid from the protected header to identify the recipient DID, looks it
    up in the local wallet, and decrypts.

    Args:
        profile: Holder's agent profile (must use Askar backend).
        jwe_compact: Compact JWE string (5 dot-separated parts).

    Returns:
        Tuple of (decrypted payload dict, recipient DID).

    Raises:
        BadJWSHeaderError: Malformed token or unsupported alg/enc.
        WalletNotFoundError: The kid DID is not in this wallet.
        WalletError: Decryption failure or unsupported wallet backend.
    """
    parts = jwe_compact.split(".")
    if len(parts) != 5:
        raise BadJWSHeaderError(
            f"Invalid compact JWE: expected 5 parts, got {len(parts)}"
        )

    header_b64, enc_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts

    try:
        header = json.loads(_from_b64url(header_b64))
    except Exception as err:
        raise BadJWSHeaderError("Invalid JWE: cannot decode protected header") from err

    alg = header.get("alg")
    enc = header.get("enc")
    kid = header.get("kid")
    epk_jwk = header.get("epk")

    if alg != JWE_ALG:
        raise BadJWSHeaderError(f"Unsupported JWE alg '{alg}', expected '{JWE_ALG}'")
    if enc != JWE_ENC:
        raise BadJWSHeaderError(f"Unsupported JWE enc '{enc}', expected '{JWE_ENC}'")
    if not kid:
        raise BadJWSHeaderError("Missing 'kid' in JWE protected header")
    if not epk_jwk:
        raise BadJWSHeaderError("Missing 'epk' in JWE protected header")

    async with profile.session() as session:
        wallet = session.inject(BaseWallet)

        from .askar import AskarWallet
        if not isinstance(wallet, AskarWallet):
            raise WalletError("JWE verify requires the Askar wallet backend")

        try:
            did_info = await wallet.get_local_did(did_lookup_name(nym_to_did(kid)))
        except WalletNotFoundError:
            raise WalletNotFoundError(
                f"DID '{kid}' not found in this wallet — "
                "only the intended recipient can decrypt this token"
            )

        try:
            key_entry = await wallet._session.handle.fetch_key(did_info.verkey)
        except AskarError as err:
            raise WalletError("Failed to fetch key from Askar store") from err

        if not key_entry:
            raise WalletNotFoundError(
                f"Private key not found for verkey: {did_info.verkey}"
            )

        try:
            x25519_key = key_entry.key.convert_key(KeyAlg.X25519)
        except AskarError as err:
            raise WalletError("Failed to convert Ed25519 key to X25519") from err

        try:
            epk = Key.from_jwk(json.dumps(epk_jwk))
        except AskarError as err:
            raise WalletError("Failed to load EPK from protected header") from err

        try:
            cek = ecdh.EcdhEs(alg, None, None).receiver_unwrap_key(
                "A256KW", enc, epk, x25519_key, _from_b64url(enc_key_b64)
            )
        except AskarError as err:
            raise WalletError("Failed to unwrap content encryption key") from err

        try:
            plaintext = cek.aead_decrypt(
                _from_b64url(ciphertext_b64),
                nonce=_from_b64url(iv_b64),
                tag=_from_b64url(tag_b64),
                aad=header_b64.encode(),
            )
        except AskarError as err:
            raise WalletError(
                "JWE decryption failed — wrong key or tampered token"
            ) from err

    return json.loads(plaintext), kid
