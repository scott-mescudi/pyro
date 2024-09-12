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

var Dir = "D:\\pgp_messanger\\bin\\keys"

func Make_Dir() {
	Dirs := []string{
		"keys",
		"keys/external",
		"keys/vault",
		"keys/vault/private",
		"keys/vault/public",
	}

	for _, i := range Dirs {
		os.Mkdir(i, os.FileMode(0755))
	}
}

func EncryptMessage(message string, pubKeyPath string) (string, error) {
	pubKeyFile, err := os.Open(pubKeyPath)
	if err != nil {
		return "", err
	}
	defer pubKeyFile.Close()

	block, err := armor.Decode(pubKeyFile)
	if err != nil {
		return "", err
	}

	entityList, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return "", err
	}

	var encrypted bytes.Buffer
	armorWriter, err := armor.Encode(&encrypted, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}

	w, err := openpgp.Encrypt(armorWriter, entityList, nil, nil, nil)
	if err != nil {
		return "", err
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		return "", err
	}

	err = w.Close()
	if err != nil {
		return "", err
	}

	err = armorWriter.Close()
	if err != nil {
		return "", err
	}

	return encrypted.String(), nil
}

func DecryptMessage(encryptedMessage string, privKeyPath string, passphrase string) (string, error) {
	privKeyFile, err := os.Open(privKeyPath)
	if err != nil {
		return "", err
	}
	defer privKeyFile.Close()

	// Decode the armored private key
	block, err := armor.Decode(privKeyFile)
	if err != nil {
		return "", err
	}

	// Parse the key
	entityList, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return "", err
	}

	entity := entityList[0]
	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		err := entity.PrivateKey.Decrypt([]byte(passphrase))
		if err != nil {
			return "", err
		}
	}

	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			err := subkey.PrivateKey.Decrypt([]byte(passphrase))
			if err != nil {
				return "", err
			}
		}
	}

	// Decode the armored encrypted message
	block, err = armor.Decode(bytes.NewBufferString(encryptedMessage))
	if err != nil {
		return "", err
	}

	// Decrypt the message
	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return "", err
	}

	message, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}

	return string(message), nil
}

func RemoveKey(file string, fle2 string) error {
	switch fle2 {
	case "external":
		err := os.Remove(filepath.Join(Dir, "external", file))
		if err != nil {
			return fmt.Errorf("error removing file: %v", err)
		}
	case "vault-private":
		err := os.Remove(filepath.Join(Dir, "vault/private", file))
		if err != nil {
			return fmt.Errorf("error removing file: %v", err)
		}
	case "vault-public":
		err := os.Remove(filepath.Join(Dir, "vault/public", file))
		if err != nil {
			return fmt.Errorf("error removing file: %v", err)
		}
	default:
		return fmt.Errorf("cannot remove %v in %v {allowed paths: 'pub', 'vault-private', 'vault-public'}", file, fle2)
	}

	return nil
}

func ListKeys(folder string, prefix string, isroot bool) {
	files, err := os.ReadDir(folder)
	if err != nil {
		panic(err)
	}

	// Print the starting folder name with a trailing slash
	if isroot {
		fmt.Printf("%s/\n", filepath.Base(folder))
	}

	for i, entry := range files {
		// Determine the proper prefix
		var newPrefix string
		if i == len(files)-1 {
			newPrefix = prefix + "└── "
		} else {
			newPrefix = prefix + "├── "
		}

		// Print the entry
		fmt.Println(newPrefix + entry.Name())

		// Recursively list subDirectories
		if entry.IsDir() {
			// Call listKeys recursively for Directories
			ListKeys(filepath.Join(folder, entry.Name()), prefix+getIndent(i, len(files)-1), false)
		}
	}
}

func Move_key(file string, fle2 string) error {
	_, err := os.Stat(file)
	if os.IsNotExist(err) {
		return fmt.Errorf("file %s does not exist", file)
	}

	switch fle2 {
	case "external":
		err = os.Rename(file, filepath.Join(Dir, "external", filepath.Base(file)))
		if err != nil {
			return fmt.Errorf("error moving file: %v", err)
		}
	case "vault-private":
		err = os.Rename(file, filepath.Join(Dir, "vault/private", filepath.Base(file)))
		if err != nil {
			return fmt.Errorf("error moving file: %v", err)
		}
	case "vault-public":
		err = os.Rename(file, filepath.Join(Dir, "vault/public", filepath.Base(file)))
		if err != nil {
			return fmt.Errorf("error moving file: %v", err)
		}
	default:
		return fmt.Errorf("cannot move %v -> %v {allowed paths: 'pub', 'vault-private', 'vault-public'}", file, fle2)
	}

	return nil
}

func Copy_file(filename, folder string) error {
	switch folder {
	case "external":
		file, err := os.ReadFile(filepath.Join(Dir, "external", filename))
		if err != nil {
			return err
		}

		err = clipboard.WriteAll(string(file))
		if err != nil {
			return err
		}
	case "vault-private":
		file, err := os.ReadFile(filepath.Join(Dir, "vault/private", filename))
		if err != nil {
			return err
		}

		err = clipboard.WriteAll(string(file))
		if err != nil {
			return err
		}

	case "vault-public":
		file, err := os.ReadFile(filepath.Join(Dir, "vault/public", filename))
		if err != nil {
			return err
		}

		err = clipboard.WriteAll(string(file))
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("path does not exist {allowed paths: 'external', 'vault-private', 'vault-public'}")
	}

	return nil
}

func getIndent(index, total int) string {
	if index == total {
		return "    " // last entry
	}
	return "│   " // not the last entry
}

func AddKey(path, folder string) error {
	scanner := bufio.NewScanner(os.Stdin)
	var lines []string

	fmt.Println("Type ':wq' on new line and press 'ENTER' to finish ")
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

	// Join lines into a single string with newline characters
	content := strings.Join(lines, "\n")

	var filePath string

	switch folder {
	case "external":
		filePath = filepath.Join(Dir, "external", path)
	case "vault-private":
		filePath = filepath.Join(Dir, "vault/private", path)
	case "vault-public":
		filePath = filepath.Join(Dir, "vault-public", path)
	default:
		return fmt.Errorf("cannot add %v in %v {allowed paths: 'external', 'vault-private', 'vault-public'}", path, folder)
	}

	// Create or open the file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close() // Ensure the file is closed after writing

	// Write content to the file
	if _, err := file.Write([]byte(content)); err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	return nil
}

func Encrypt_message(key string, gh string) error {
	fmt.Printf("Please enter you message to encrypt: %v ", gh)

	scanner := bufio.NewScanner(os.Stdin)
	var lines []string

	fmt.Println("Type ':wq' on new line and press 'ENTER' to finish")
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

	var keypath string
	if gh == "vault-private" {
		keypath = filepath.Join(Dir, "vault/private", key)
	} else if gh == "vault-public" {
		keypath = filepath.Join(Dir, "vault/public", key)
	} else {
		keypath = filepath.Join(Dir, "external", key)
	}

	encryptmsg, err := EncryptMessage(content, keypath)
	if err != nil {
		return fmt.Errorf("error encrypting message: %w", err)
	}

	fmt.Println("\nEncrypted message is:\n", encryptmsg)
	clipboard.WriteAll(encryptmsg)
	return nil
}

func Decrypt_message(key string) error {
	fmt.Printf("Please enter you message to decrypt: ")

	scanner := bufio.NewScanner(os.Stdin)
	var lines []string

	fmt.Println("Type ':wq' on new line and press 'ENTER' to finish")
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
	keypath := filepath.Join(Dir, "vault/private", key)

	decryptmsg, err := DecryptMessage(content, keypath, "")
	if err != nil {
		return fmt.Errorf("error decrypting message: %w", err)
	}

	fmt.Println("\nDecrypted message is:\n", decryptmsg)
	clipboard.WriteAll(decryptmsg)
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
go run main.go -init
go run main.go -list vault
go run main.go -add mykey external
go run main.go -mv mykey vault-private
go run main.go -rm mykey external
go run main.go -copy mykey vault-private
go run main.go -encrypt recipient_pubkey external
go run main.go -decrypt my_private_key
`
