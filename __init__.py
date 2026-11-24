"""StegVault: hide encrypted text or files inside images using keyed LSB steganography."""

from .stego import (
    Payload,
    StegError,
    WrongPasswordError,
    capacity,
    hide,
    reveal,
    lsb_plane,
)

__all__ = [
    "Payload",
    "StegError",
    "WrongPasswordError",
    "capacity",
    "hide",
    "reveal",
    "lsb_plane",
]

__version__ = "1.0.0"
