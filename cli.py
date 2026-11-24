"""Command-line interface for StegVault."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import __version__
from .stego import (
    ALLOWED_BITS,
    KIND_FILE,
    KIND_TEXT,
    Payload,
    StegError,
    capacity,
    hide,
    lsb_plane,
    reveal,
)


def _get_password(args: argparse.Namespace, confirm: bool) -> str:
    if args.password_file:
        return Path(args.password_file).read_text(encoding="utf-8").strip()
    if args.password:
        print("warning: passing a password on the command line can leak it via shell history.",
              file=sys.stderr)
        return args.password
    pw = getpass.getpass("Password: ")
    if confirm and getpass.getpass("Confirm password: ") != pw:
        raise StegError("Passwords do not match.")
    return pw


def _add_password_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("-p", "--password", help="password (prompted securely if omitted)")
    g.add_argument("--password-file", help="read the password from a file")


def cmd_hide(args: argparse.Namespace) -> None:
    if args.file:
        path = Path(args.file)
        payload = Payload(KIND_FILE, path.read_bytes(), filename=path.name)
    elif args.message is not None:
        payload = Payload(KIND_TEXT, args.message.encode("utf-8"))
    else:
        print("Enter message, then Ctrl-D (Ctrl-Z Enter on Windows):", file=sys.stderr)
        payload = Payload(KIND_TEXT, sys.stdin.read().encode("utf-8"))

    password = _get_password(args, confirm=True)
    stats = hide(args.cover, args.output, password, payload, bits=args.bits)
    print(f"Hidden {stats['payload_bytes']:,} bytes in {stats['output']}")
    print(f"  capacity used : {stats['usage_percent']:.2f}% of {stats['capacity_bytes']:,} bytes")
    print(f"  values changed: {stats['changed_values']:,}")
    print(f"  PSNR          : {stats['psnr_db']:.2f} dB")


def cmd_reveal(args: argparse.Namespace) -> None:
    password = _get_password(args, confirm=False)
    payload = reveal(args.image, password)

    if payload.kind == KIND_TEXT and not args.output:
        print(payload.text)
        return

    out = Path(args.output or args.output_dir or ".")
    if out.is_dir():
        out = out / (payload.filename or "message.txt")
    if out.exists() and not args.force:
        raise StegError(f"'{out}' already exists (use --force to overwrite).")
    out.write_bytes(payload.data)
    print(f"Extracted {len(payload.data):,} bytes to {out}")


def cmd_capacity(args: argparse.Namespace) -> None:
    for bits in ([args.bits] if args.bits else ALLOWED_BITS):
        print(f"{bits} bit(s)/channel: {capacity(args.image, bits):,} bytes (after compression)")


def cmd_plane(args: argparse.Namespace) -> None:
    lsb_plane(args.image, args.output, bit=args.bit)
    print(f"Saved bit plane {args.bit} to {args.output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegvault",
        description="Hide AES-encrypted text or files inside images with keyed LSB steganography.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("hide", help="hide a message or file inside an image")
    p.add_argument("cover", help="cover image (any format Pillow can read)")
    p.add_argument("output", help="output image (.png, .bmp or .tiff)")
    src = p.add_mutually_exclusive_group()
    src.add_argument("-m", "--message", help="text message to hide (stdin if omitted)")
    src.add_argument("-f", "--file", help="file to hide")
    p.add_argument("-b", "--bits", type=int, choices=ALLOWED_BITS, default=1,
                   help="LSBs used per colour channel (default 1; higher = more space, less stealth)")
    _add_password_args(p)
    p.set_defaults(func=cmd_hide)

    p = sub.add_parser("reveal", help="extract hidden data from an image")
    p.add_argument("image")
    p.add_argument("-o", "--output", help="write the payload to this path")
    p.add_argument("-d", "--output-dir", help="directory for extracted files (keeps original name)")
    p.add_argument("--force", action="store_true", help="overwrite existing files")
    _add_password_args(p)
    p.set_defaults(func=cmd_reveal)

    p = sub.add_parser("capacity", help="show how much data an image can hold")
    p.add_argument("image")
    p.add_argument("-b", "--bits", type=int, choices=ALLOWED_BITS)
    p.set_defaults(func=cmd_capacity)

    p = sub.add_parser("plane", help="export a bit plane of an image for visual analysis")
    p.add_argument("image")
    p.add_argument("output")
    p.add_argument("--bit", type=int, default=0, help="bit index, 0 = least significant")
    p.set_defaults(func=cmd_plane)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except StegError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
