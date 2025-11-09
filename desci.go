package main

import (
	"strings"
	"io/ioutil"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"path/filepath"
	"log"
	"io/fs"
)

var validExts = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".gif":  true,
	".docx": true,
	".xlsx": true,
	".pptx": true,
	".pdf":  true,
}

func recorrerDescrifrando(root string, passphrase string) error {
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if validExts[ext] {
			log.Printf("Descrifrando: %s\n", path)
			DecryptFile(path, passphrase)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
func deriveKeyDirect(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

func DecryptFile(path string, passphrase string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	key := deriveKeyDirect(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Fixed IV = first 16 bytes of key (deterministic, NOT secure for repeated plaintext)
	iv := key[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)

	ciphertext := make([]byte, len(data))
	mode.CryptBlocks(ciphertext, data)

	outPath := path
	if err := ioutil.WriteFile(outPath, ciphertext, 0600); err != nil {
		return err
	}
	return nil
}

func main() {

	passphrase := "comoMolo"
	Dir := "/Users/dani/Unileon/fundamentos/malware/prueba"

	log.Printf("Recorriendo: %s\n", Dir)
	err := recorrerDescrifrando(Dir, passphrase)
	if err != nil {
		log.Fatalf("Error recorriendo directorio: %v\n", err)
	}
}
