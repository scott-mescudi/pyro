package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	m "pgp/app/modules"

)

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
		m.ListKeys(filepath.Join(m.Dir, "external"), "", true)
	case "vault":
		m.ListKeys(filepath.Join(m.Dir, "vault"), "", true)
	case "all":
		m.ListKeys(m.Dir, "", true)

	}

	if ms2 && len(os.Args) == 2 {
		err := m.Decrypt_message(os.Args[2])
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Message decrypted successfully and copied to clipboard")
	} else if start {
		m.Make_Dir()
	} else if msg {
		if len(os.Args) > 3 {
			err := m.Encrypt_message(os.Args[2], os.Args[3])
			if err != nil {
				fmt.Println(err)
				return
			}
		} else {
			err := m.Encrypt_message(os.Args[2], "")
			if err != nil {
				fmt.Println(err)
				return
			}
		}

		fmt.Println("Message encrypted successfully and copied to clipboard")

	} else if move && len(os.Args) == 3 {
		err := m.Move_key(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Key added successfully")
	} else if rmkey && len(os.Args) == 3 {
		err := m.RemoveKey(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Key removed successfully")
	} else if copy && len(os.Args) == 3 {
		err := m.Copy_file(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Key copied to clipboard successfully")
	} else if add && len(os.Args) == 3 {
		err := m.AddKey(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Key added successfully")
	} else if generate && len(os.Args) == 4{
		pubkey, privkey, err := m.GenerateKeyPair()
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
		fmt.Println(m.HelpMessage)
	}

}