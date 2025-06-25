package main

import (
	"log"
	"socks5/proxy"
)

func main() {
	addr := ":24512"
	log.Printf("SOCKS5 proxy listening on %s...\n", addr)
	if err := proxy.Start(addr); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
