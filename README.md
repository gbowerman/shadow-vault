# shadow-vault
Code for researching deniable encryption. Create a vault with multiple encrypted slots, some containing encrypted data, some containing random data, with no provable difference.

## Overview

Shadow Vault creates encrypted vaults that can contain two independent datasets, each encrypted with a different password. When decrypted with one password, it reveals one dataset; when decrypted with the other password, it reveals a different dataset. If you only provide one dataset during encryption, the tool automatically generates fake ciphertext for the second slot, making it indistinguishable from a real encrypted dataset.

## Features

- **Dual-dataset encryption**: Store two independent datasets in a single file
- **Plausible deniability**: The existence of a second dataset is cryptographically hidden
- **Strong encryption**: Uses AES-256 in CTR mode with Scrypt key derivation
- **Flexible input**: Encrypt text strings or file contents
- **Block interleaving**: Datasets are interleaved at the block level for security

## Requirements

```
pip install cryptography
cd code
```

## Examples

### Example 1: Create a vault with two sets of data:

```
python shadow.py --encrypt \
  --datastring "Grocery list: milk, eggs, bread" \
  --password "pass phrase 1" \
  --datastring2 "Bank account: 123456789, PIN: 4321" \
  --password2 "pass phrase 2" \
  --out personal.vault

# Decrypt the first data set
python shadow.py --decrypt --password "pass phrase 1" --in personal.vault

# Decrypt the second data set
python shadow.py --decrypt --password "pass phrase 2" --in personal.vault --block 2
```

### Example 2: Encrypt two different files:

```
# Encrypt
python shadow.py --encrypt \
  --datafile endymion.txt \
  --password "pass phrase 1" \
  --datafile2 hyperion.txt \
  --password2 "pass phrase 2" \
  --out poems.vault

# Decrypt first file
python shadow.py --decrypt --password "pass phrase 1" --in poems.vault > endymion.txt

# Decrypt second file
python shadow.py --decrypt --password "pass phrase 2" --in poems.vault --block 2 > hyperion.txt
```

### Example 3: Single dataset interleaved with random text

```
# Encrypt one dataset (random data automatically generated for second slot)
python shadow.py --encrypt \
  --datastring "My secret message" \
  --password "my pass phrase" \
  --out shadow.vault

# Decrypt
python shadow.py --decrypt --password "my pass phrase" --in shadow.vault
```
