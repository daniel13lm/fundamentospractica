package main

import (
	"log"
	"net"
)

var protocolo = "tcp"

var listener = "localhost:8989"

func handler(conn net.Conn) {
	defer conn.Close()
	log.Println("conexion entrante", conn)
	if _, err := conn.Write([]byte("Z3:uc12wcH9>")); err != nil {
		log.Fatal(err)
	}
}

func main() {
	listen, err := net.Listen(protocolo, listener)
	if err != nil {
		log.Fatal("error al establecer la escucha", err)
	}

	log.Printf("escuchando conexiones entrantes")

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Println("error al la conexiones", err)

		}
		go handler(conn)
	}
}
