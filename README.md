<div align="center">

# 🔐 StegVault

**Hide AES-256-encrypted messages and files inside ordinary images, using password-keyed LSB steganography.**

![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)
![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-success)
![KDF](https://img.shields.io/badge/KDF-scrypt-informational)
![Tests](https://img.shields.io/badge/tests-16%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

</div>

---

## 📖 Overview

**Steganography** hides the fact that a message exists at all. **Encryption** keeps the message secret even if it is found. StegVault does both.

It writes encrypted data into the **least significant bits (LSBs)** of an image's pixels. These are changes of ±1 in a colour value, which the eye can't see. Many simple LSB tools write bits in order from the first pixel and protect them with a basic XOR cipher. StegVault instead:

- encrypts everything with **AES-256-GCM** (authenticated encryption),
- derives keys from your password with **scrypt** (slow to brute-force, salted), and
- **scatters** the bits across the whole image in an order only the correct password can reproduce.

<div align="center">
<img src="docs/lsb_comparison.png" alt="LSB plane comparison: sequential embedding leaves a visible band, StegVault's scattered embedding blends in as noise" width="100%">
<br><sub>Same 4 KB payload in the same image. Sequential embedding leaves a visible band in the LSB plane; StegVault spreads it across the whole image.</sub>
</div>

---

## ✨ Features

| | |
|---|---|
| 🔑 **Strong cryptography** | scrypt with a random 16-byte salt produces two independent 256-bit keys: one for AES-256-GCM, one for pixel ordering |
| 🎲 **Keyed scattering** | Bits go to pseudo-random positions from an AES-CTR keystream, identical on every platform |
| 🛡️ **Tamper detection** | A wrong password or an edited image raises a clear error instead of returning garbage |
| 📁 **Text or any file** | Hide a message or a PDF, ZIP or anything else. Filenames are kept, and data is compressed first |
| ⚖️ **Adjustable density** | 1, 2 or 4 LSBs per channel, trading stealth for capacity |
| 🖼️ **Alpha-safe** | Transparent PNGs keep their alpha channel untouched |
| 📊 **Embedding stats** | Capacity used, values changed, and PSNR image-quality score |
| 🔬 **Analysis tools** | Capacity calculator and bit-plane export for visual steganalysis |
| ✅ **Tested** | 16 pytest tests: round-trips, wrong passwords, tampering, limits and CLI |

---

## 🚀 Quick start

```bash
git clone https://github.com/<your-username>/stegvault.git
cd stegvault
pip install -e .
```

Requires **Python 3.9+**. Dependencies: Pillow, NumPy, cryptography.

```bash
# Hide a message (you'll be asked for a password)
stegvault hide photo.png secret.png -m "Meet at 7, north entrance"

# Reveal it
stegvault reveal secret.png
```

> If the `stegvault` command isn't found, use `python -m stegvault` instead.

---

## 🧭 Usage

### Hide

```bash
stegvault hide <cover-image> <output.png> [-m TEXT | -f FILE] [-b 1|2|4]
```

```bash
stegvault hide photo.jpg secret.png -m "top secret"   # text
stegvault hide photo.jpg secret.png -f plans.pdf      # any file
stegvault hide photo.jpg secret.png -f big.zip -b 2   # more capacity
```

Example output:

```
Hidden 17 bytes in secret.png
  capacity used : 0.01% of 777,583 bytes
  values changed: 316
  PSNR          : 91.07 dB
```

### Reveal

```bash
stegvault reveal secret.png                 # prints text
stegvault reveal secret.png -d extracted/   # saves files with their original name
stegvault reveal secret.png -o out.bin      # saves to a specific path
```

### Analyse

```bash
stegvault capacity photo.png        # how much fits at 1, 2 and 4 bits
stegvault plane secret.png lsb.png  # export the LSB plane as an image
```

### Use as a Python library

```python
from stegvault import Payload, hide, reveal
from stegvault.stego import KIND_TEXT

stats = hide("photo.png", "secret.png", "my password", Payload(KIND_TEXT, b"hello"))
print(reveal("secret.png", "my password").text)   # -> hello
```

---

## ⚙️ How it works

```
password ──scrypt(salt)──► 64 bytes ─┬─► AES-256-GCM key  ──► encrypts payload
                                     └─► permutation key  ──► AES-CTR keystream ──► pixel order

Image RGB channel values
┌───────────────┬──────────────────────────────────────────────────────────┐
│ header (136)  │ body: remaining values, visited in keyed random order    │
│ salt + flags  │ [length][nonce][ciphertext][auth tag]                    │
└───────────────┴──────────────────────────────────────────────────────────┘
```

1. **Pack.** Type, filename and zlib-compressed data are combined into one plaintext.
2. **Encrypt.** AES-256-GCM with a random nonce. The header is authenticated as associated data, so it can't be altered unnoticed.
3. **Header.** The salt and a settings byte go into the first 136 channel values at 1 bit each. They aren't secret, but they're needed to derive the keys.
4. **Scatter.** The encrypted body is written into the LSBs of the remaining values in an order produced by sorting an AES-CTR keystream. This is deterministic and doesn't depend on NumPy's RNG.
5. **Reveal.** Read the salt, re-derive both keys, rebuild the order, read the body, then verify and decrypt.

Hiding the same message twice produces two different images, because each run uses a fresh random salt and nonce.

---

## 📂 Project structure

```
stegvault/
├── stegvault/
│   ├── crypto.py      # scrypt KDF, AES-GCM, keyed permutation
│   ├── stego.py       # embedding / extraction, capacity, bit planes
│   ├── cli.py         # command-line interface
│   └── __main__.py    # `python -m stegvault`
├── tests/
│   └── test_stegvault.py
├── docs/
│   └── lsb_comparison.png
├── pyproject.toml
└── requirements.txt
```

---

## ⚠️ Limitations

- **Lossless output only.** Save as PNG, BMP or TIFF. JPEG compression, resizing, or uploading to most social networks destroys hidden data. Send images as files.
- **Statistical steganalysis.** Tests such as chi-square or RS analysis can still detect LSB embedding, especially at 2–4 bits per channel or high capacity use. Small payloads in large, detailed photos are hardest to detect.
- **Password strength matters.** scrypt slows brute-force attacks, but a weak password is still weak.

This project is built for **learning and cybersecurity practice**.

---

## 🧪 Running tests

```bash
pip install -e ".[test]"
pytest
```

---

## 🗺️ Roadmap

- [ ] Desktop GUI
- [ ] Adaptive embedding (prefer textured/noisy regions over smooth areas)
- [ ] Built-in chi-square steganalysis report
- [ ] Audio (WAV) cover support

---

## 👤 Author

**<Your Name>** · [LinkedIn](https://linkedin.com/in/<your-profile>) · [GitHub](https://github.com/<your-username>)

## 📄 License

[MIT](LICENSE)
