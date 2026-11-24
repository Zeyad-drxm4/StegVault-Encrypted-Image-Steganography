import numpy as np
import pytest
from PIL import Image

from stegvault import Payload, StegError, WrongPasswordError, capacity, hide, lsb_plane, reveal
from stegvault.cli import main
from stegvault.crypto import keyed_permutation
from stegvault.stego import KIND_FILE, KIND_TEXT


@pytest.fixture
def cover(tmp_path):
    rng = np.random.default_rng(0)
    arr = rng.integers(0, 256, size=(120, 160, 3), dtype=np.uint8)
    path = tmp_path / "cover.png"
    Image.fromarray(arr).save(path)
    return path


@pytest.mark.parametrize("bits", [1, 2, 4])
def test_text_roundtrip(cover, tmp_path, bits):
    out = tmp_path / "stego.png"
    msg = "Meet at the old library at 7 — bring the key 🔑"
    hide(cover, out, "correct horse", Payload(KIND_TEXT, msg.encode()), bits=bits)
    result = reveal(out, "correct horse")
    assert result.is_text and result.text == msg


def test_file_roundtrip(cover, tmp_path):
    secret = tmp_path / "notes.bin"
    secret.write_bytes(bytes(range(256)) * 10)
    out = tmp_path / "stego.png"
    hide(cover, out, "pw", Payload(KIND_FILE, secret.read_bytes(), filename="notes.bin"))
    result = reveal(out, "pw")
    assert result.filename == "notes.bin"
    assert result.data == secret.read_bytes()


def test_wrong_password(cover, tmp_path):
    out = tmp_path / "stego.png"
    hide(cover, out, "right", Payload(KIND_TEXT, b"secret"))
    with pytest.raises(WrongPasswordError):
        reveal(out, "wrong")


def test_clean_image_has_no_data(cover):
    with pytest.raises(WrongPasswordError):
        reveal(cover, "anything")


def test_tampering_detected(cover, tmp_path):
    out = tmp_path / "stego.png"
    hide(cover, out, "pw", Payload(KIND_TEXT, b"x" * 2000))
    arr = np.array(Image.open(out))
    arr[60:, :, :] ^= 1  # flip LSBs in the bottom half
    Image.fromarray(arr).save(out)
    with pytest.raises(WrongPasswordError):
        reveal(out, "pw")


def test_too_large(cover, tmp_path):
    big = np.random.default_rng(1).bytes(100_000)  # incompressible
    with pytest.raises(StegError, match="too large"):
        hide(cover, tmp_path / "o.png", "pw", Payload(KIND_TEXT, big))


def test_rejects_lossy_output(cover, tmp_path):
    with pytest.raises(StegError, match="lossless"):
        hide(cover, tmp_path / "o.jpg", "pw", Payload(KIND_TEXT, b"hi"))


def test_alpha_preserved(tmp_path):
    arr = np.zeros((50, 50, 4), dtype=np.uint8)
    arr[..., 3] = np.arange(50, dtype=np.uint8)[None, :] * 5
    src, out = tmp_path / "a.png", tmp_path / "b.png"
    Image.fromarray(arr, "RGBA").save(src)
    hide(src, out, "pw", Payload(KIND_TEXT, b"alpha test"))
    result = np.array(Image.open(out))
    assert result.shape[2] == 4
    assert np.array_equal(result[..., 3], arr[..., 3])
    assert reveal(out, "pw").text == "alpha test"


def test_only_lsbs_change(cover, tmp_path):
    out = tmp_path / "stego.png"
    hide(cover, out, "pw", Payload(KIND_TEXT, b"hello" * 100), bits=1)
    a = np.array(Image.open(cover)).astype(int)
    b = np.array(Image.open(out)).astype(int)
    assert np.abs(a - b).max() <= 1


def test_embedding_is_scattered(cover, tmp_path):
    """Changes should be spread over the image, not packed at the start."""
    out = tmp_path / "stego.png"
    hide(cover, out, "pw", Payload(KIND_TEXT, b"z" * 300))
    a, b = np.array(Image.open(cover)), np.array(Image.open(out))
    changed_rows = np.unique(np.nonzero(a != b)[0])
    assert changed_rows.max() > 100


def test_permutation_is_deterministic_and_valid():
    p1 = keyed_permutation(b"k" * 32, 1000)
    p2 = keyed_permutation(b"k" * 32, 1000)
    p3 = keyed_permutation(b"j" * 32, 1000)
    assert np.array_equal(p1, p2)
    assert not np.array_equal(p1, p3)
    assert np.array_equal(np.sort(p1), np.arange(1000))


def test_same_input_gives_different_images(cover, tmp_path):
    """Random salt + nonce mean hiding the same message twice looks different."""
    o1, o2 = tmp_path / "1.png", tmp_path / "2.png"
    for o in (o1, o2):
        hide(cover, o, "pw", Payload(KIND_TEXT, b"same"))
    assert not np.array_equal(np.array(Image.open(o1)), np.array(Image.open(o2)))


def test_capacity_and_plane(cover, tmp_path):
    assert capacity(cover, 1) < capacity(cover, 2) < capacity(cover, 4)
    lsb_plane(cover, tmp_path / "plane.png")
    assert Image.open(tmp_path / "plane.png").size == (160, 120)


def test_cli_roundtrip(cover, tmp_path, capsys):
    out = tmp_path / "s.png"
    assert main(["hide", str(cover), str(out), "-m", "cli works", "-p", "pw"]) == 0
    capsys.readouterr()
    assert main(["reveal", str(out), "-p", "pw"]) == 0
    assert capsys.readouterr().out.strip() == "cli works"
    assert main(["reveal", str(out), "-p", "nope"]) == 1
