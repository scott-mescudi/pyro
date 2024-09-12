# PGP Key Management Tool - README

This program provides a simple interface for managing PGP (Pretty Good Privacy) keys, encrypting/decrypting messages, and organizing PGP key directories. It helps users handle their PGP keys and perform common cryptographic tasks like encryption, decryption, key addition, and removal.

## Features

- Initialize PGP key directories.
- Add, remove, and move PGP keys between directories.
- Encrypt messages using a public key.
- Decrypt messages using a private key.
- Copy PGP keys to the clipboard.
- List keys stored in different directories.

## Prerequisites

- **Go** must be installed on your machine to run the program.
- **Clipboard support** is enabled using the `github.com/atotto/clipboard` package. Ensure your system supports clipboard operations.

## Directory Structure

The program works with a predefined set of directories to store your keys:
- `keys/`: Root directory.
- `keys/external/`: Directory for storing external public keys.
- `keys/vault/private/`: Directory for storing private keys.
- `keys/vault/public/`: Directory for storing internal public keys.

The directory structure is automatically created when you initialize the program.

## Usage

To use the program, execute the Go file with various flags and options. Below are the commands and examples:

### 1. Initialize Key Directories

This command creates the necessary directories for key management.

```bash
./GO-pgp -init
```

### 2. List PGP Keys

List the keys in different directories. Available options:
- `pub` - Lists external public keys.
- `vault` - Lists keys in the vault (both private and public).
- `all` - Lists all available keys.

```bash
./GO-pgp -list vault
```

### 3. Add a PGP Key

Add a new key manually to one of the directories. You can add it to `external`, `vault-private`, or `vault-public`.

```bash
./GO-pgp -add mykey external
```

The program will allow you to enter the PGP key content line-by-line. Type `:wq` to save and exit.

### 4. Move a Key

Move a key file to another directory.

```bash
./GO-pgp -mv mykey vault-private
```

### 5. Remove a PGP Key

Remove a key from one of the directories.

```bash
./GO-pgp -rm mykey external
```

### 6. Copy a Key to Clipboard

Copy the content of a key file to the system clipboard.

```bash
./GO-pgp -copy mykey vault-private
```

### 7. Encrypt a Message

Encrypt a message using a public key. Provide the key name and the directory where it's stored.

```bash
./GO-pgp -encrypt recipient_pubkey external
```

The program will prompt you to enter the message. Type `:wq` to finish, and the encrypted message will be printed and copied to the clipboard.

### 8. Decrypt a Message

Decrypt a message using a private key. The private key must be located in the `vault-private` directory.

```bash
./GO-pgp -decrypt my_private_key
```

The program will prompt you to enter the encrypted message. Type `:wq` to finish, and the decrypted message will be printed and copied to the clipboard.

## Command Overview

```plaintext
-init
	Initialize the PGP key directories.

-list <directory>
	List all PGP keys in the specified directory.
	Options: 'pub', 'vault', 'all'

-add <key_filename> <directory>
	Add a new PGP key.
	Options: 'external', 'vault-private', 'vault-public'

-mv <file_path> <destination_directory>
	Move a key file.
	Options: 'external', 'vault-private', 'vault-public'

-rm <key_filename> <directory>
	Remove a PGP key.
	Options: 'external', 'vault-private', 'vault-public'

-copy <key_filename> <directory>
	Copy the content of a key to the clipboard.
	Options: 'external', 'vault-private', 'vault-public'

-encrypt <key_filename> <directory>
	Encrypt a message using the specified public key.

-decrypt <key_filename>
	Decrypt a message using the specified private key.
```

## Examples

- **Initialize the tool**:
  ```bash
  ./GO-pgp -init
  ```

- **Add a new key to the external directory**:
  ```bash
  ./GO-pgp -add mykey external
  ```

- **Encrypt a message using an external public key**:
  ```bash
  ./GO-pgp -encrypt recipient_pubkey external
  ```

- **Decrypt a message using a private key**:
  ```bash
  ./GO-pgp -decrypt my_private_key
  ```

## Notes

- The program supports both public and private key operations.
- Ensure that the required key files are stored in the appropriate directories before performing encryption or decryption.
- The clipboard is used for convenient transfer of encrypted/decrypted messages and keys.
