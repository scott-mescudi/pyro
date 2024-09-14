package modules

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/atotto/clipboard"
)

var Dir = "/pyro/src/keys/"

func Make_Dir() {
	Dirs := []string{
		"keys",
		"keys/external",
		"keys/vault",
		"keys/vault/private",
		"keys/vault/public",
	}

	for _, i := range Dirs {
		if err := os.MkdirAll(i, os.FileMode(0755)); err != nil && !os.IsExist(err) {
			fmt.Printf("Error creating directory '%s': %v\n", i, err)
		}
	}
}

func EncryptMessage(message string, pubKeyPath string) (string, error) {
	pubKeyFile, err := os.Open(pubKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to open public key file '%s': %w", pubKeyPath, err)
	}
	defer pubKeyFile.Close()

	block, err := armor.Decode(pubKeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to decode armored public key file: %w", err)
	}

	entityList, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read public key ring: %w", err)
	}

	var encrypted bytes.Buffer
	armorWriter, err := armor.Encode(&encrypted, "PGP MESSAGE", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create armor writer: %w", err)
	}

	w, err := openpgp.Encrypt(armorWriter, entityList, nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt message: %w", err)
	}

	if _, err := w.Write([]byte(message)); err != nil {
		return "", fmt.Errorf("failed to write message: %w", err)
	}

	if err := w.Close(); err != nil {
		return "", fmt.Errorf("failed to close encryption writer: %w", err)
	}

	if err := armorWriter.Close(); err != nil {
		return "", fmt.Errorf("failed to close armor writer: %w", err)
	}

	return encrypted.String(), nil
}

func DecryptMessage(encryptedMessage string, privKeyPath string, passphrase string) (string, error) {
	privKeyFile, err := os.Open(privKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to open private key file '%s': %w", privKeyPath, err)
	}
	defer privKeyFile.Close()

	block, err := armor.Decode(privKeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to decode armored private key file: %w", err)
	}

	entityList, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read private key ring: %w", err)
	}

	entity := entityList[0]
	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		if err := entity.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
			return "", fmt.Errorf("failed to decrypt private key: %w", err)
		}
	}

	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			if err := subkey.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
				return "", fmt.Errorf("failed to decrypt subkey: %w", err)
			}
		}
	}

	block, err = armor.Decode(bytes.NewBufferString(encryptedMessage))
	if err != nil {
		return "", fmt.Errorf("failed to decode armored message: %w", err)
	}

	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return "", fmt.Errorf("failed to read message: %w", err)
	}

	message, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", fmt.Errorf("failed to read message body: %w", err)
	}

	return string(message), nil
}

func RemoveKey(file string, fle2 string) error {
	var err error
	switch fle2 {
	case "external":
		err = os.Remove(filepath.Join(Dir, "external", file))
	case "vault-private":
		err = os.Remove(filepath.Join(Dir, "vault/private", file))
	case "vault-public":
		err = os.Remove(filepath.Join(Dir, "vault/public", file))
	default:
		return fmt.Errorf("invalid path '%v' for removing key '%v' {allowed paths: 'external', 'vault-private', 'vault-public'}", fle2, file)
	}

	if err != nil {
		return fmt.Errorf("error removing file '%v' from '%v': %w", file, fle2, err)
	}

	return nil
}

func ListKeys(folder string, prefix string, isroot bool) error {
	files, err := os.ReadDir(folder)
	if err != nil {
		return fmt.Errorf("failed to list directory '%s': %v", folder, err)
	}

	if isroot {
		fmt.Printf("%s/\n", filepath.Base(folder))
	}

	for i, entry := range files {
		var newPrefix string
		if i == len(files)-1 {
			newPrefix = prefix + "└── "
		} else {
			newPrefix = prefix + "├── "
		}

		fmt.Println(newPrefix + entry.Name())

		if entry.IsDir() {
			ListKeys(filepath.Join(folder, entry.Name()), prefix+getIndent(i, len(files)-1), false)
		}
	}

	return nil
}

func Move_key(file string, fle2 string) error {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return fmt.Errorf("file '%s' does not exist", file)
	}

	var err error
	switch fle2 {
	case "external":
		err = os.Rename(file, filepath.Join(Dir, "external", filepath.Base(file)))
	case "vault-private":
		err = os.Rename(file, filepath.Join(Dir, "vault/private", filepath.Base(file)))
	case "vault-public":
		err = os.Rename(file, filepath.Join(Dir, "vault/public", filepath.Base(file)))
	default:
		return fmt.Errorf("invalid destination '%v' for moving key '%v' {allowed paths: 'external', 'vault-private', 'vault-public'}", fle2, file)
	}

	if err != nil {
		return fmt.Errorf("error moving file '%v' to '%v': %w", file, fle2, err)
	}

	return nil
}

func Copy_file(filename, folder string) error {
	var filePath string
	switch folder {
	case "external":
		filePath = filepath.Join(Dir, "external", filename)
	case "vault-private":
		filePath = filepath.Join(Dir, "vault/private", filename)
	case "vault-public":
		filePath = filepath.Join(Dir, "vault/public", filename)
	default:
		return fmt.Errorf("invalid folder '%v' {allowed paths: 'external', 'vault-private', 'vault-public'}", folder)
	}

	file, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading file '%v' from '%v': %w", filename, folder, err)
	}

	if err := clipboard.WriteAll(string(file)); err != nil {
		return fmt.Errorf("error copying file '%v' to clipboard: %w", filename, err)
	}

	return nil
}

func AddKey(path, folder string) error {
	scanner := bufio.NewScanner(os.Stdin)
	var lines []string

	fmt.Println("Type ':wq' on a new line and press 'ENTER' to finish input.")
	for scanner.Scan() {
		line := scanner.Text()
		if line == ":wq" {
			break
		}
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading input: %w", err)
	}

	content := strings.Join(lines, "\n")
	var filePath string

	switch folder {
	case "external":
		filePath = filepath.Join(Dir, "external", path)
	case "vault-private":
		filePath = filepath.Join(Dir, "vault/private", path)
	case "vault-public":
		filePath = filepath.Join(Dir, "vault/public", path)
	default:
		return fmt.Errorf("invalid folder '%v' for adding key '%v' {allowed paths: 'external', 'vault-private', 'vault-public'}", folder, path)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file '%v': %w", filePath, err)
	}
	defer file.Close()

	if _, err := file.Write([]byte(content)); err != nil {
		return fmt.Errorf("error writing to file '%v': %w", filePath, err)
	}

	return nil
}

func Encrypt_message(key string, gh string) error {
	message, err := readInput("Please enter your message to encrypt: ")
	if err!= nil {
        return fmt.Errorf("error reading message input: %w", err)
    }
	encryptedMessage, err := EncryptMessage(message, key)
	if err != nil {
		return fmt.Errorf("error encrypting message: %w", err)
	}

	fmt.Println("Encrypted Message:")
	fmt.Println(encryptedMessage)

	return nil
}

func getIndent(index, total int) string {
	if index == total {
		return "    "
	}
	return "│   "
}

func readInput(prompt string) (string, error) {
    fmt.Println(prompt)

    scanner := bufio.NewScanner(os.Stdin)
    var lines []string

    fmt.Println("Type ':wq' on a new line and press 'ENTER' to finish input.")
    for scanner.Scan() {
        line := scanner.Text()
        if line == ":wq" {
            break
        }
        lines = append(lines, line)
    }

    if err := scanner.Err(); err != nil {
        return "", fmt.Errorf("error reading input: %w", err)
    }

    return strings.Join(lines, "\n"), nil
}


func Decrypt_message(key string) error {
	content, err := readInput("Please enter your message to decrypt: ")
	if err!= nil {
        return fmt.Errorf("error reading message input: %w", err)
    }
	keypath := filepath.Join(Dir, "vault/private", key)

	// Decrypt the message
	decryptedMessage, err := DecryptMessage(content, keypath, "")
	if err != nil {
		return fmt.Errorf("error decrypting message: %w", err)
	}

	// Print decrypted message
	fmt.Println("\nDecrypted message is:\n", decryptedMessage)

	// Copy to clipboard
	if err := clipboard.WriteAll(decryptedMessage); err != nil {
		return fmt.Errorf("error copying decrypted message to clipboard: %w", err)
	}

	return nil
}


func GenerateKeyPair() (string, string, error) {
	entity, err := openpgp.NewEntity("", "", "", nil)
	if err != nil {
		return "", "", err
	}

	// Serialize the private key.
	var privateKeyBuf bytes.Buffer
	privateKeyWriter, err := armor.Encode(&privateKeyBuf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", "", err
	}
	err = entity.SerializePrivate(privateKeyWriter, nil)
	if err != nil {
		return "", "", err
	}
	privateKeyWriter.Close()

	// Serialize the public key.
	var publicKeyBuf bytes.Buffer
	publicKeyWriter, err := armor.Encode(&publicKeyBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", "", err
	}
	err = entity.Serialize(publicKeyWriter)
	if err != nil {
		return "", "", err
	}
	publicKeyWriter.Close()

	return publicKeyBuf.String(), privateKeyBuf.String(), nil
}

var HelpMessage = `Usage of PGP Key Management Tool:
-init
	Initialize the PGP key Directories.

-list <Directory>
	List all PGP keys in the specified Directory.
	Available options: 'pub', 'vault', 'all'

-add <key_filename> <Directory>
	Add a new PGP key to the specified Directory.
	Available Directories: 'external', 'vault-private', 'vault-public'

-mv <file_path> <destination_Directory>
	Move a key file to the specified Directory.
	Available Directories: 'external', 'vault-private', 'vault-public'

-rm <key_filename> <Directory>
	Remove a PGP key from the specified Directory.
	Available Directories: 'external', 'vault-private', 'vault-public'

-copy <key_filename> <Directory>
	Copy the content of a key file to the clipboard.
	Available Directories: 'external', 'vault-private', 'vault-public'

-encrypt <key_filename> <Directory>
	Encrypt a message using the specified public key.

-decrypt <key_filename>
	Decrypt a message using the specified private key from 'vault-private' Directory.

Examples:
./pyro -init
./pyro -list vault
./pyro -add mykey external
./pyro -mv mykey vault-private
./pyro -rm mykey external
./pyro -copy mykey vault-private
./pyro -encrypt recipient_pubkey external
./pyro -decrypt my_private_key
`