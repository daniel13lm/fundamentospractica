package main

import (
	"fmt"
	"encoding/base64"
	"strings"
)

func ofuscarTexto(texto string) string {
	pay := base64.StdEncoding.EncodeToString([]byte(texto))
	var result strings.Builder
	for _, c := range pay {
		switch {
		case 'A' <= c && c <= 'Z':
			result.WriteRune('A' + (c-'A'+13)%26)
		case 'a' <= c && c <= 'z':
			result.WriteRune('a' + (c-'a'+13)%26)
		default:
			result.WriteRune(c)
		}
	}
	return result.String()
}

func main() {

	s := "Hello and welcome"
	s = ofuscarTexto(s)
	fmt.Printf("ofuscado s: %s!\n", s)

}
