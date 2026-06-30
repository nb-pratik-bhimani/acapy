"""BitstringStatusList / StatusList2021 revocation status checker for JSON-LD credentials."""

import base64
import gzip
import logging
import zlib
from typing import Optional, Union

import requests

LOGGER = logging.getLogger(__name__)

SUPPORTED_ENTRY_TYPES = {"BitstringStatusListEntry", "StatusList2021Entry"}
SUPPORTED_LIST_TYPES = {"BitstringStatusList", "StatusList2021"}


class BitstringStatusListError(Exception):
    """Raised when a credential status check fails or cannot be completed."""


async def check_credential_status(credential: dict) -> bool:
    """Return True if the credential is revoked via credentialStatus, False if valid.

    Supports BitstringStatusListEntry and StatusList2021Entry.
    If credentialStatus is absent the credential is treated as not revoked.

    Raises:
        BitstringStatusListError: if the status list cannot be fetched or decoded.
    """
    credential_status = credential.get("credentialStatus")
    if not credential_status:
        return False

    if isinstance(credential_status, list):
        for entry in credential_status:
            if await _check_entry(entry):
                return True
        return False

    return await _check_entry(credential_status)


async def _check_entry(entry: dict) -> bool:
    """Check a single credentialStatus entry."""
    entry_type = entry.get("type")
    if entry_type not in SUPPORTED_ENTRY_TYPES:
        LOGGER.warning(
            "Unsupported credentialStatus type %s — skipping status check", entry_type
        )
        return False

    if entry.get("statusPurpose", "revocation") != "revocation":
        return False

    status_list_url = entry.get("statusListCredential")
    status_list_index = entry.get("statusListIndex")

    if not status_list_url or status_list_index is None:
        raise BitstringStatusListError(
            "credentialStatus entry is missing statusListCredential or statusListIndex"
        )

    status_list_credential = _fetch_status_list_credential(status_list_url)

    credential_subject = status_list_credential.get("credentialSubject", {})
    list_type = credential_subject.get("type")
    if list_type and list_type not in SUPPORTED_LIST_TYPES:
        LOGGER.warning(
            "Unsupported status list type %s — skipping status check", list_type
        )
        return False

    encoded_list = credential_subject.get("encodedList")
    if not encoded_list:
        raise BitstringStatusListError(
            f"Status list credential at {status_list_url} has no encodedList"
        )

    return _is_bit_set(encoded_list, int(status_list_index))


def _fetch_status_list_credential(url: str) -> dict:
    """Fetch and return the status list credential JSON from the given URL."""
    try:
        response = requests.get(
            url,
            headers={"Accept": "application/json, application/ld+json"},
            timeout=10,
        )
        response.raise_for_status()
        return response.json()
    except Exception as err:
        raise BitstringStatusListError(
            f"Failed to fetch status list credential from {url}: {err}"
        ) from err


def _is_bit_set(encoded_list: str, index: int) -> bool:
    """Decode encodedList and check whether the bit at index is set (1 = revoked).

    Handles both formats:
    - BitstringStatusList: multibase 'u' prefix → base64url-no-pad → gzip
    - StatusList2021:      plain base64 (with or without padding) → gzip
    """
    # Multibase base64url (no padding), prefix 'u'
    if encoded_list.startswith("u"):
        b64 = encoded_list[1:]
        # Restore padding
        b64 += "=" * (-len(b64) % 4)
        compressed = base64.urlsafe_b64decode(b64)
    else:
        b64 = encoded_list
        b64 += "=" * (-len(b64) % 4)
        compressed = base64.b64decode(b64)

    # Decompress — gzip first, fall back to raw zlib
    try:
        bitstring = gzip.decompress(compressed)
    except OSError:
        try:
            bitstring = zlib.decompress(compressed)
        except zlib.error as err:
            raise BitstringStatusListError(
                f"Failed to decompress status list encodedList: {err}"
            ) from err

    byte_index = index // 8
    bit_index = 7 - (index % 8)  # MSB first within each byte

    if byte_index >= len(bitstring):
        raise BitstringStatusListError(
            f"statusListIndex {index} is out of bounds "
            f"(list length {len(bitstring) * 8} bits)"
        )

    return bool(bitstring[byte_index] & (1 << bit_index))
