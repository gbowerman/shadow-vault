#!/usr/bin/env python3

# Shadow vault - deniable encryption app
# Implements a dual-dataset encryption approach

import argparse
import os
import sys
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 1024  # storage block size in bytes
MAGIC = b"SHAD"
VERSION = 1


@dataclass
class DatasetMeta:
    salt: bytes
    iv: bytes


@dataclass
class Header:
    version: int
    ds1: DatasetMeta
    len1: int
    ds2: DatasetMeta
    len2: int

# Utility functions

# Load data from string or file
def load_data(datastring: str | None, datafile: str | None) -> bytes:
    if datastring is not None:
        return datastring.encode("utf-8")
    if datafile is not None:
        with open(datafile, "rb") as f:
            return f.read()
    return None


# Derive a key from password and salt using Scrypt KDF
def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))

# AES-CTR encryption/decryption
def encrypt_aes_ctr(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

# AES-CTR decryption
def decrypt_aes_ctr(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# PKCS7 padding/unpadding
def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()  # AES block size = 128 bits
    return padder.update(data) + padder.finalize()

# PKCS7 unpadding
def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


# Storage padding (not PKCS7)
def pad_to_block_size(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Pad arbitrary data to a multiple of block_size with random bytes.
    This is NOT PKCS7, just storage padding.
    """
    remainder = len(data) % block_size
    if remainder == 0:
        return data
    pad_len = block_size - remainder
    return data + os.urandom(pad_len)

# Split data into blocks of block_size
def split_into_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    if len(data) % block_size != 0:
        raise ValueError("Data length must be a multiple of block size")
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

# Header construction and parsing
def build_header() -> Header:
    # Always provision metadata for two datasets
    salt1 = os.urandom(16)
    iv1 = os.urandom(16)
    ds1 = DatasetMeta(salt1, iv1)

    salt2 = os.urandom(16)
    iv2 = os.urandom(16)
    ds2 = DatasetMeta(salt2, iv2)

    # lengths will be set after encryption
    return Header(VERSION, ds1, len1=0, ds2=ds2, len2=0)

# Serialize header to bytes
def serialize_header(h: Header) -> bytes:
    """
    Format:
    MAGIC(4) | VERSION(1) |
    LEN1(8, big-endian) | SALT1(16) | IV1(16) |
    LEN2(8, big-endian) | SALT2(16) | IV2(16)
    """
    out = bytearray()
    out += MAGIC
    out += bytes([h.version])

    out += h.len1.to_bytes(8, "big")
    out += h.ds1.salt
    out += h.ds1.iv

    out += h.len2.to_bytes(8, "big")
    out += h.ds2.salt
    out += h.ds2.iv

    return bytes(out)

# Parse header from bytes
def parse_header(data: bytes) -> Tuple[Header, int]:
    """
    Returns (Header, header_length).
    """
    # MAGIC(4) + VER(1) + LEN1(8) + SALT1(16) + IV1(16) + LEN2(8) + SALT2(16) + IV2(16)
    min_len = 4 + 1 + 8 + 16 + 16 + 8 + 16 + 16
    if len(data) < min_len:
        raise ValueError("File too short to contain valid header")

    offset = 0
    magic = data[offset:offset + 4]
    offset += 4
    if magic != MAGIC:
        raise ValueError("Invalid magic header")

    version = data[offset]
    offset += 1

    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}")

    len1 = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    salt1 = data[offset:offset + 16]
    offset += 16
    iv1 = data[offset:offset + 16]
    offset += 16
    ds1 = DatasetMeta(salt1, iv1)

    len2 = int.from_bytes(data[offset:offset + 8], "big")
    offset += 8
    salt2 = data[offset:offset + 16]
    offset += 16
    iv2 = data[offset:offset + 16]
    offset += 16
    ds2 = DatasetMeta(salt2, iv2)

    header = Header(version, ds1, len1, ds2, len2)
    return header, offset

# Interleaving and extraction of datasets
def interleave_two_datasets(cipher1_padded: bytes, cipher2_padded: bytes) -> bytes:
    """
    Layout:
    [data1_block0, data2_block0, data1_block1, data2_block1, ...]
    Both inputs must already be multiples of BLOCK_SIZE.
    """
    blocks1 = split_into_blocks(cipher1_padded)
    blocks2 = split_into_blocks(cipher2_padded)

    n1 = len(blocks1)
    n2 = len(blocks2)
    max_n = max(n1, n2)

    # Pad shorter list with random blocks so both have same number of blocks
    while len(blocks1) < max_n:
        blocks1.append(os.urandom(BLOCK_SIZE))
    while len(blocks2) < max_n:
        blocks2.append(os.urandom(BLOCK_SIZE))

    out = bytearray()
    for i in range(max_n):
        out += blocks1[i]
        out += blocks2[i]
    return bytes(out)

# Extract blocks for a specific dataset
def extract_blocks_for_dataset(data_area: bytes, which: int) -> bytes:
    """
    which: 1 or 2 (block index set)

    Layout is always:
      [ds1_block0, ds2_block0, ds1_block1, ds2_block1, ...]

    which == 1 -> indices 0,2,4,...
    which == 2 -> indices 1,3,5,...
    """
    if which not in (1, 2):
        raise ValueError("which must be 1 or 2")

    if len(data_area) % BLOCK_SIZE != 0:
        raise ValueError("Corrupted file: data area not aligned to block size")

    blocks = split_into_blocks(data_area)

    start_index = 0 if which == 1 else 1
    selected = blocks[start_index::2]
    return b"".join(selected)

# Fake ciphertext generation for dataset 2
def make_fake_ciphertext_for_dataset2(header: Header) -> bytes:
    """
    Generate a fake ciphertext stream for dataset 2 when the user
    did not provide real data2. This looks like real ciphertext:
      - random plaintext of random length
      - PKCS7-padded
      - encrypted with a key derived from a random password
    """
    # Choose a random plausible plaintext length (e.g., 16..4096 bytes)
    fake_plain_len = os.urandom(2)
    fake_plain_len = 16 + int.from_bytes(fake_plain_len, "big") % (4096 - 16 + 1)

    fake_plain = os.urandom(fake_plain_len)
    fake_padded = pkcs7_pad(fake_plain)

    # Derive a key from a random "fake" password
    fake_password = os.urandom(32).hex()
    key2 = derive_key(fake_password, header.ds2.salt)
    cipher2 = encrypt_aes_ctr(key2, header.ds2.iv, fake_padded)

    header.len2 = len(cipher2)
    cipher2_padded = pad_to_block_size(cipher2, BLOCK_SIZE)
    return cipher2_padded

# Main program logic
def encrypt_mode(args: argparse.Namespace) -> None:
    # Load primary dataset
    data1 = load_data(args.datastring, args.datafile)
    if data1 is None:
        print("Error: You must provide --datastring or --datafile for the primary dataset", file=sys.stderr)
        sys.exit(1)

    if not args.password:
        print("Error: --password is required", file=sys.stderr)
        sys.exit(1)

    # Load secondary dataset (optional)
    data2 = load_data(args.datastring2, args.datafile2)
    has_second_dataset = data2 is not None

    if has_second_dataset and not args.password2:
        print("Error: --password2 is required when providing a second dataset", file=sys.stderr)
        sys.exit(1)

    if not args.out:
        print("Error: --out is required", file=sys.stderr)
        sys.exit(1)

    header = build_header()

    # Dataset 1 (real)
    key1 = derive_key(args.password, header.ds1.salt)
    padded1 = pkcs7_pad(data1)
    cipher1 = encrypt_aes_ctr(key1, header.ds1.iv, padded1)
    header.len1 = len(cipher1)
    cipher1_padded = pad_to_block_size(cipher1, BLOCK_SIZE)

    # Dataset 2 (real or fake)
    if has_second_dataset:
        key2 = derive_key(args.password2, header.ds2.salt)  # type: ignore
        padded2 = pkcs7_pad(data2)
        cipher2 = encrypt_aes_ctr(key2, header.ds2.iv, padded2)
        header.len2 = len(cipher2)
        cipher2_padded = pad_to_block_size(cipher2, BLOCK_SIZE)
    else:
        cipher2_padded = make_fake_ciphertext_for_dataset2(header)

    interleaved = interleave_two_datasets(cipher1_padded, cipher2_padded)

    header_bytes = serialize_header(header)
    output = header_bytes + interleaved

    with open(args.out, "wb") as f:
        f.write(output)

    print(f"Encrypted data written to {args.out}")

# Decrypt mode
def decrypt_mode(args: argparse.Namespace) -> None:
    if not args.password:
        print("Error: --password is required for --decrypt", file=sys.stderr)
        sys.exit(1)

    if not args.input_file:
        print("Error: --in is required for --decrypt", file=sys.stderr)
        sys.exit(1)

    which_block = args.block
    if which_block not in (1, 2):
        print("Error: --block must be 1 or 2", file=sys.stderr)
        sys.exit(1)

    with open(args.input_file, "rb") as f:
        contents = f.read()

    header, offset = parse_header(contents)
    data_area = contents[offset:]

    # Select metadata and length for the chosen dataset
    if which_block == 1:
        ds_meta = header.ds1
        true_len = header.len1
    else:
        ds_meta = header.ds2
        true_len = header.len2

    key = derive_key(args.password, ds_meta.salt)
    cipher_for_ds_padded = extract_blocks_for_dataset(data_area, which_block)

    # Truncate back to the true ciphertext length before decrypting
    cipher_for_ds = cipher_for_ds_padded[:true_len]

    try:
        padded_plain = decrypt_aes_ctr(key, ds_meta.iv, cipher_for_ds)
        plain = pkcs7_unpad(padded_plain)
    except Exception as e:
        print(f"Decryption failed (wrong password or corrupted file): {e}", file=sys.stderr)
        sys.exit(1)

    # Print to stdout
    sys.stdout.write(plain.decode("utf-8", errors="replace"))
    if not plain.endswith(b"\n"):
        sys.stdout.write("\n")

# Argument parsing
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Shadow-style deniable encryption prototype")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--encrypt", action="store_true", help="Encrypt mode")
    mode.add_argument("--decrypt", action="store_true", help="Decrypt mode")

    # Primary dataset input
    primary_input = parser.add_mutually_exclusive_group()
    primary_input.add_argument("--datastring", help="Primary plaintext as a string")
    primary_input.add_argument("--datafile", help="Primary plaintext loaded from a file")

    # Secondary dataset input
    secondary_input = parser.add_mutually_exclusive_group()
    secondary_input.add_argument("--datastring2", help="Secondary plaintext as a string")
    secondary_input.add_argument("--datafile2", help="Secondary plaintext loaded from a file")

    parser.add_argument("--password", help="Primary password / pass phrase")
    parser.add_argument("--password2", help="Secondary password / pass phrase (hidden)")

    parser.add_argument("--out", help="Output file for encryption")
    parser.add_argument("--in", dest="input_file", help="Input file for decryption")

    parser.add_argument(
        "--block",
        type=int,
        default=1,
        help="For decrypt: which block set to use (1 or 2). 1 = primary, 2 = hidden",
    )

    return parser.parse_args()

# Main entry point
def main() -> None:
    args = parse_args()
    if args.encrypt:
        encrypt_mode(args)
    elif args.decrypt:
        decrypt_mode(args)
    else:
        print("Either --encrypt or --decrypt must be specified", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
