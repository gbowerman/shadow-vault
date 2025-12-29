# shadow-vault
Code for researching deniable encryption. Create a vault with multiple encrypted slots, some containing encrypted data, some containing random data, with no provable difference.

## Examples

### Example 1: Create a vault with two sets of data:

```
python shadow.py --encrypt \
  --datastring "Grocery list: milk, eggs, bread" \
  --password "groceries123" \
  --datastring2 "Bank account: 123456789, PIN: 4321" \
  --password2 "MyRealSecurePassword!2025" \
  --out personal.vault

# Decrypt the first data set
python shadow.py --decrypt --password "groceries123" --in personal.vault

# Decrypt the second data set
python shadow.py --decrypt --password "MyRealSecurePassword!2025" --in personal.vault --block 2
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
