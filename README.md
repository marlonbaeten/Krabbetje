<img src="https://raw.githubusercontent.com/marlonbaeten/krabbetje/main/krabbetje.svg" width="400" alt="Krabbetje logo" />

# Krabbetje vault

## Encrypt and decrypt files using a passphrase or key

Krabbetje is a command line interface tool that allows the user to
encrypt or decrypt the contents of a file. It is intended to allow the user to
commit secret (configuration) files in a repository without leaking them
when a repository gets compromised and prevent the secrets from appearing
on disk in plain.

## Features

- Encrypt or decrypt UTF8 encoded text files
- Encrypt or decrypt only the values of Yaml files
- Uses AES 256 GCM for encryption and PBKDF2 + SHA 256 for key derivation

## Caveats

- Only supports UTF8 encoded files
- The resulting ciphertext files are larger than the originals, since they
are base64 encoded and contain the salt that is used to derive a key from the
passphrase
- Each ciphertext contains a special header to identify Krabbetje encrypted
files
- Yaml files are always parsed, the root keys are left in plain and all values
are encrypted
- Yaml files especially grow in size since there is a salt per value

## Usage

Krabbetje wil automatically detect if the provided file is a krabbetje vault
and either encrypt or decrypt its contents accordingly and print the result to
stdout.

To view the encrypted/decrypted contents of a file:

```
krabbetje <file>
```

or pipe the resulting ciphertext/plaintext to a file:

```
krabbetje <file> > <target_file>
```

## Disclaimer

This software should never be used. Do not use this software ever, in any
situation or circumstance.
