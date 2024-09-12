package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// Function to generate a PGP key pair (public and private keys).
func generateKeyPair() (string, string, error) {
	// Create a new entity (key pair) with the given identity and email.
	entity, err := openpgp.NewEntity("Test User", "test", "test@example.com", nil)
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



func main() {
	// x := []string{"tom", "json", "mark"}

	// for _, i := range x{
	// 	publicKey, privateKey, err := generateKeyPair()
	// 	if err != nil {
	// 		fmt.Println("Error generating key pair:", err)
	// 		return
	// 	}

	// 	file, _:= os.Create("D:\\pgp_messanger\\keys\\public_keys\\" + i + "_public.asc")
	// 	file.Write([]byte(publicKey))

	// 	file, _ = os.Create("D:\\pgp_messanger\\privkeys\\" + i + "_private.asc")
	// 	file.Write([]byte(privateKey))
	// }

		publicKey, privateKey, err := generateKeyPair()
		if err != nil {
			fmt.Println("Error generating key pair:", err)
			return
		}

		file, _:= os.Create("anish_public.asc")
		file.Write([]byte(publicKey))

		file, _ = os.Create("anish_private.asc")
		file.Write([]byte(privateKey))
}
