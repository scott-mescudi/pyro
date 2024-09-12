package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/atotto/clipboard"
)

var dir = "D:\\pgp_messanger\\bin\\keys"

func make_dir() {
	dirs := []string{
		"keys",
		"keys/external",
		"keys/vault",
		"keys/vault/private",
		"keys/vault/public",
	}

	for _, i := range dirs {
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

func removeKey(file string, fle2 string) error {
	switch fle2 {
	case "external":
		err := os.Remove(filepath.Join(dir, "external", file))
		if err != nil {
			return fmt.Errorf("error removing file: %v", err)
		}
	case "vault-private":
		err := os.Remove(filepath.Join(dir, "vault/private", file))
		if err != nil {
			return fmt.Errorf("error removing file: %v", err)
		}
	case "vault-public":
		err := os.Remove(filepath.Join(dir, "vault/public", file))
		if err != nil {
			return fmt.Errorf("error removing file: %v", err)
		}
	default:
		return fmt.Errorf("cannot remove %v in %v {allowed paths: 'pub', 'vault-private', 'vault-public'}", file, fle2)
	}

	return nil
}

func listKeys(folder string, prefix string, isroot bool) {
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

		// Recursively list subdirectories
		if entry.IsDir() {
			// Call listKeys recursively for directories
			listKeys(filepath.Join(folder, entry.Name()), prefix+getIndent(i, len(files)-1), false)
		}
	}
}

func move_key(file string, fle2 string) error {
	_, err := os.Stat(file)
	if os.IsNotExist(err) {
		return fmt.Errorf("file %s does not exist", file)
	}

	switch fle2 {
	case "external":
		err = os.Rename(file, filepath.Join(dir, "external", filepath.Base(file)))
		if err != nil {
			return fmt.Errorf("error moving file: %v", err)
		}
	case "vault-private":
		err = os.Rename(file, filepath.Join(dir, "vault/private", filepath.Base(file)))
		if err != nil {
			return fmt.Errorf("error moving file: %v", err)
		}
	case "vault-public":
		err = os.Rename(file, filepath.Join(dir, "vault/public", filepath.Base(file)))
		if err != nil {
			return fmt.Errorf("error moving file: %v", err)
		}
	default:
		return fmt.Errorf("cannot move %v -> %v {allowed paths: 'pub', 'vault-private', 'vault-public'}", file, fle2)
	}

	return nil
}

func copy_file(filename, folder string) error {
	switch folder {
	case "external":
		file, err := os.ReadFile(filepath.Join(dir, "external", filename))
		if err != nil {
			return err
		}

		err = clipboard.WriteAll(string(file))
		if err != nil {
			return err
		}
	case "vault-private":
		file, err := os.ReadFile(filepath.Join(dir, "vault/private", filename))
		if err != nil {
			return err
		}

		err = clipboard.WriteAll(string(file))
		if err != nil {
			return err
		}

	case "vault-public":
		file, err := os.ReadFile(filepath.Join(dir, "vault/public", filename))
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

func addKey(path, folder string) error {
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
		filePath = filepath.Join(dir, "external", path)
	case "vault-private":
		filePath = filepath.Join(dir, "vault/private", path)
	case "vault-public":
		filePath = filepath.Join(dir, "vault-public", path)
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

func encrypt_message(key string, gh string) error {
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
		keypath = filepath.Join(dir, "vault/private", key)
	} else if gh == "vault-public" {
		keypath = filepath.Join(dir, "vault/public", key)
	} else {
		keypath = filepath.Join(dir, "external", key)
	}

	encryptmsg, err := EncryptMessage(content, keypath)
	if err != nil {
		return fmt.Errorf("error encrypting message: %w", err)
	}

	fmt.Println("\nEncrypted message is:\n", encryptmsg)
	clipboard.WriteAll(encryptmsg)
	return nil
}

func decrypt_message(key string) error {
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
	keypath := filepath.Join(dir, "vault/private", key)

	decryptmsg, err := DecryptMessage(content, keypath, "")
	if err != nil {
		return fmt.Errorf("error decrypting message: %w", err)
	}

	fmt.Println("\nDecrypted message is:\n", decryptmsg)
	clipboard.WriteAll(decryptmsg)
	return nil
}

func generateKeyPair() (string, string, error) {
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


var helpMessage = `Usage of PGP Key Management Tool:
-init
	Initialize the PGP key directories.

-list <directory>
	List all PGP keys in the specified directory.
	Available options: 'pub', 'vault', 'all'

-add <key_filename> <directory>
	Add a new PGP key to the specified directory.
	Available directories: 'external', 'vault-private', 'vault-public'

-mv <file_path> <destination_directory>
	Move a key file to the specified directory.
	Available directories: 'external', 'vault-private', 'vault-public'

-rm <key_filename> <directory>
	Remove a PGP key from the specified directory.
	Available directories: 'external', 'vault-private', 'vault-public'

-copy <key_filename> <directory>
	Copy the content of a key file to the clipboard.
	Available directories: 'external', 'vault-private', 'vault-public'

-encrypt <key_filename> <directory>
	Encrypt a message using the specified public key.

-decrypt <key_filename>
	Decrypt a message using the specified private key from 'vault-private' directory.

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

func main() {
	var (
		list  string
		move  bool
		rmkey bool
		copy  bool
		add   bool
		msg   bool
		ms2   bool
		start bool
		generate bool
	)

	flag.StringVar(&list, "list", "", "List all PGP keys")
	flag.BoolVar(&move, "mv", false, "Add a new PGP key")
	flag.BoolVar(&rmkey, "rm", false, "Remove a PGP key")
	flag.BoolVar(&copy, "copy", false, "Copy PGP key to clipboard")
	flag.BoolVar(&add, "add", false, "Add a new PGP key")
	flag.BoolVar(&msg, "encrypt", false, "Encrypt a message")
	flag.BoolVar(&ms2, "decrypt", false, "Decrypt a message")
	flag.BoolVar(&start, "init", false, "Start the PGP key management tool")
	flag.BoolVar(&generate, "generate", false, "Generate a new PGP key pair")

	flag.Parse()

	switch list {
	case "pub":
		listKeys(filepath.Join(dir, "external"), "", true)
	case "vault":
		listKeys(filepath.Join(dir, "vault"), "", true)
	case "all":
		listKeys(dir, "", true)

	}

	if ms2 && len(os.Args) == 2 {
		err := decrypt_message(os.Args[2])
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Message decrypted successfully and copied to clipboard")
	} else if start {
		make_dir()
	} else if msg {
		if len(os.Args) > 3 {
			err := encrypt_message(os.Args[2], os.Args[3])
			if err != nil {
				fmt.Println(err)
				return
			}
		} else {
			err := encrypt_message(os.Args[2], "")
			if err != nil {
				fmt.Println(err)
				return
			}
		}

		fmt.Println("Message encrypted successfully and copied to clipboard")

	} else if move && len(os.Args) == 3 {
		err := move_key(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Key added successfully")
	} else if rmkey && len(os.Args) == 3 {
		err := removeKey(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Key removed successfully")
	} else if copy && len(os.Args) == 3 {
		err := copy_file(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Key copied to clipboard successfully")
	} else if add && len(os.Args) == 3 {
		err := addKey(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Key added successfully")
	} else if generate && len(os.Args) == 4{
		pubkey, privkey, err := generateKeyPair()
		if err != nil{
			fmt.Println("Error generating key pair:", err)
            return
		}

		pubPath := fmt.Sprintf("%v_pub.asc",os.Args[2])
		privPath := fmt.Sprintf("%v_priv.asc",os.Args[3])

		if pubkey == privPath {
			fmt.Println("Error: Public and private key file names cannot be the same.")
            return
		}

		file, err := os.Create(pubPath)
		if err!= nil {
            fmt.Println("Error creating private key file:", err)
            return
        }
		file.Write([]byte(pubkey))

		file, err = os.Create(privPath)
		if err!= nil {
            fmt.Println("Error creating private key file:", err)
            return
        }
		file.Write([]byte(privkey))

	}else {
		fmt.Println(helpMessage)
	}

}

	// publicKey, privateKey, err := generateKeyPair()
	// if err != nil {
	// 	fmt.Println("Error generating key pair:", err)
	// 	return
	// }

	// file, _:= os.Create("anish_public.asc")
	// file.Write([]byte(publicKey))

	// file, _ = os.Create("anish_private.asc")
	// file.Write([]byte(privateKey))