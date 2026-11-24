"""Keyed LSB steganography.

Layout inside the image's RGB channel values (alpha is never touched):

    [ header: 136 channel values, 1 bit each, in natural order ]
        16 bytes  scrypt salt
         1 byte   settings  (high nibble = format version, low nibble = bits per channel)

    [ body: every remaining channel value, visited in a password-derived random order,
            `bits` least-significant bits each ]
         4 bytes  length of the encrypted blob (big-endian)
         N bytes  encrypted blob = nonce || AES-256-GCM(ciphertext) || tag

The plaintext inside the blob is:
         1 byte   kind (0 = text, 1 = file)
         2 bytes  filename length
         M bytes  filename (UTF-8)
         ...      zlib-compressed data

The header is authenticated as associated data, so changing it breaks decryption.
"""

from __future__ import annotations

import math
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from PIL import Image

from . import crypto

FORMAT_VERSION = 1
ALLOWED_BITS = (1, 2, 4)
HEADER_BYTES = crypto.SALT_SIZE + 1
HEADER_SLOTS = HEADER_BYTES * 8
LENGTH_BYTES = 4
LOSSLESS_SUFFIXES = {".png", ".bmp", ".tif", ".tiff"}

KIND_TEXT = 0
KIND_FILE = 1


class StegError(Exception):
    """Base error for anything that goes wrong while hiding or revealing."""


class WrongPasswordError(StegError):
    """The password is wrong, the image holds no hidden data, or it was modified."""


@dataclass
class Payload:
    kind: int
    data: bytes
    filename: str | None = None

    @property
    def is_text(self) -> bool:
        return self.kind == KIND_TEXT

    @property
    def text(self) -> str:
        return self.data.decode("utf-8")


# --------------------------------------------------------------------------- #
# Image helpers
# --------------------------------------------------------------------------- #

def _load(path: str | Path) -> tuple[np.ndarray, str]:
    """Load an image as a uint8 array with 3 (RGB) or 4 (RGBA) channels."""
    try:
        img = Image.open(path)
        img.load()
    except (OSError, FileNotFoundError) as exc:
        raise StegError(f"Could not open image '{path}': {exc}") from exc

    has_alpha = img.mode in ("RGBA", "LA", "PA") or (
        img.mode == "P" and "transparency" in img.info
    )
    mode = "RGBA" if has_alpha else "RGB"
    return np.array(img.convert(mode), dtype=np.uint8), mode


def _rgb_view(arr: np.ndarray) -> np.ndarray:
    """Flat copy of the RGB channel values (alpha excluded)."""
    return arr[..., :3].reshape(-1).copy()


def _write_rgb(arr: np.ndarray, flat_rgb: np.ndarray) -> np.ndarray:
    out = arr.copy()
    out[..., :3] = flat_rgb.reshape(arr.shape[0], arr.shape[1], 3)
    return out


# --------------------------------------------------------------------------- #
# Bit packing
# --------------------------------------------------------------------------- #

def _to_chunks(data: bytes, bits: int) -> np.ndarray:
    """Split bytes into `bits`-wide unsigned values, most significant first."""
    bit_array = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    weights = (1 << np.arange(bits - 1, -1, -1)).astype(np.uint8)
    return (bit_array.reshape(-1, bits) * weights).sum(axis=1).astype(np.uint8)


def _from_chunks(chunks: np.ndarray, bits: int) -> bytes:
    shifts = np.arange(bits - 1, -1, -1, dtype=np.uint8)
    bit_array = ((chunks[:, None] >> shifts) & 1).astype(np.uint8).reshape(-1)
    return np.packbits(bit_array).tobytes()


def _embed(values: np.ndarray, data: bytes, bits: int) -> np.ndarray:
    chunks = _to_chunks(data, bits)
    mask = np.uint8(0xFF ^ ((1 << bits) - 1))
    return (values[: len(chunks)] & mask) | chunks


def _extract(values: np.ndarray, n_bytes: int, bits: int) -> bytes:
    n_slots = n_bytes * 8 // bits
    chunks = values[:n_slots] & np.uint8((1 << bits) - 1)
    return _from_chunks(chunks, bits)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def _check_bits(bits: int) -> None:
    if bits not in ALLOWED_BITS:
        raise StegError(f"bits must be one of {ALLOWED_BITS}, got {bits}.")


def _body_capacity_bytes(n_values: int, bits: int) -> int:
    return max(0, (n_values - HEADER_SLOTS) * bits // 8)


def capacity(image_path: str | Path, bits: int = 1) -> int:
    """Maximum number of compressed payload bytes the image can carry."""
    _check_bits(bits)
    arr, _ = _load(image_path)
    n_values = arr.shape[0] * arr.shape[1] * 3
    overhead = LENGTH_BYTES + crypto.NONCE_SIZE + crypto.TAG_SIZE + 3
    return max(0, _body_capacity_bytes(n_values, bits) - overhead)


def _pack_plaintext(payload: Payload) -> bytes:
    name = (payload.filename or "").encode("utf-8")
    if len(name) > 0xFFFF:
        raise StegError("Filename is too long.")
    return struct.pack(">BH", payload.kind, len(name)) + name + zlib.compress(payload.data, 9)


def _unpack_plaintext(plaintext: bytes) -> Payload:
    kind, name_len = struct.unpack(">BH", plaintext[:3])
    name = plaintext[3 : 3 + name_len].decode("utf-8") or None
    data = zlib.decompress(plaintext[3 + name_len :])
    return Payload(kind=kind, data=data, filename=name)


def hide(
    cover_path: str | Path,
    output_path: str | Path,
    password: str,
    payload: Payload,
    bits: int = 1,
) -> dict:
    """Encrypt `payload` and hide it in `cover_path`, writing a lossless image to `output_path`.

    Returns a dict of statistics about the embedding.
    """
    _check_bits(bits)
    output_path = Path(output_path)
    if output_path.suffix.lower() not in LOSSLESS_SUFFIXES:
        raise StegError(
            f"Output must be a lossless format ({', '.join(sorted(LOSSLESS_SUFFIXES))}); "
            "JPEG and other lossy formats destroy hidden bits."
        )

    arr, mode = _load(cover_path)
    flat = _rgb_view(arr)
    original = flat.copy()

    salt = crypto.new_salt()
    header = salt + bytes([(FORMAT_VERSION << 4) | bits])
    enc_key, perm_key = crypto.derive_keys(password, salt)

    blob = crypto.encrypt(enc_key, _pack_plaintext(payload), associated_data=header)
    body = struct.pack(">I", len(blob)) + blob

    available = _body_capacity_bytes(flat.size, bits)
    if len(body) > available:
        raise StegError(
            f"Payload too large: needs {len(body):,} bytes, image holds {available:,} bytes "
            f"at {bits} bit(s) per channel. Use a bigger image or a higher --bits value."
        )

    # Header: fixed positions, 1 bit each.
    flat[:HEADER_SLOTS] = _embed(flat[:HEADER_SLOTS], header, 1)

    # Body: scattered across the rest of the image in password-derived order.
    order = HEADER_SLOTS + crypto.keyed_permutation(perm_key, flat.size - HEADER_SLOTS)
    used = order[: len(body) * 8 // bits]
    flat[used] = _embed(flat[used], body, bits)

    out = _write_rgb(arr, flat)
    Image.fromarray(out, mode=mode).save(output_path)

    diff = original.astype(np.int16) - flat.astype(np.int16)
    mse = float(np.mean(diff.astype(np.float64) ** 2))
    psnr = math.inf if mse == 0 else 10 * math.log10(255**2 / mse)
    return {
        "payload_bytes": len(payload.data),
        "embedded_bytes": len(body) + HEADER_BYTES,
        "capacity_bytes": available,
        "usage_percent": 100 * len(body) / available,
        "changed_values": int(np.count_nonzero(diff)),
        "psnr_db": psnr,
        "output": str(output_path),
    }


def reveal(stego_path: str | Path, password: str) -> Payload:
    """Extract and decrypt the payload hidden in `stego_path`."""
    arr, _ = _load(stego_path)
    flat = _rgb_view(arr)
    if flat.size <= HEADER_SLOTS:
        raise StegError("Image is too small to contain hidden data.")

    header = _extract(flat[:HEADER_SLOTS], HEADER_BYTES, 1)
    salt, settings = header[: crypto.SALT_SIZE], header[-1]
    version, bits = settings >> 4, settings & 0x0F
    if version != FORMAT_VERSION or bits not in ALLOWED_BITS:
        raise WrongPasswordError("No StegVault data found in this image.")

    enc_key, perm_key = crypto.derive_keys(password, salt)
    order = HEADER_SLOTS + crypto.keyed_permutation(perm_key, flat.size - HEADER_SLOTS)
    body_values = flat[order]

    (blob_len,) = struct.unpack(">I", _extract(body_values, LENGTH_BYTES, bits))
    available = _body_capacity_bytes(flat.size, bits)
    min_blob = crypto.NONCE_SIZE + crypto.TAG_SIZE
    if not (min_blob <= blob_len <= available - LENGTH_BYTES):
        raise WrongPasswordError(
            "Wrong password, or this image holds no StegVault data."
        )

    body = _extract(body_values, LENGTH_BYTES + blob_len, bits)
    try:
        plaintext = crypto.decrypt(enc_key, body[LENGTH_BYTES:], associated_data=header)
    except crypto.DecryptionError as exc:
        raise WrongPasswordError(
            "Wrong password, or the image was modified after the data was hidden."
        ) from exc
    return _unpack_plaintext(plaintext)


def lsb_plane(image_path: str | Path, output_path: str | Path, bit: int = 0) -> None:
    """Save a visualisation of one bit plane (bit 0 = LSB), amplified to black/white.

    Useful for comparing a cover and a stego image: sequential LSB embedding shows up
    as a visible band, while StegVault's scattered embedding looks like noise.
    """
    if not 0 <= bit <= 7:
        raise StegError("bit must be between 0 and 7.")
    arr, _ = _load(image_path)
    plane = ((arr[..., :3] >> bit) & 1) * 255
    Image.fromarray(plane.astype(np.uint8), mode="RGB").save(output_path)
