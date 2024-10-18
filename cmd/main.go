package main

import (
	"bulbasaur/internal/server"
	"bulbasaur/package/config"
	"flag"
	"log"
)

func main() {
	configPath := flag.String("c", "", "config file path")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("require config file path")
	}
	cfg, err := config.ReadConfig(*configPath)
	if err != nil {
		log.Fatalf("err while reading config file: %v", err)
	}
	server.Serve(&cfg)
}
