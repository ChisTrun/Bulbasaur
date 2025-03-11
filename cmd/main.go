package main

import (
	"bulbasaur/pkg/carbon/pkg/config"

	_ "github.com/go-sql-driver/mysql"

	"bulbasaur/internal/server"
)

func main() {
	flags := config.ParseFlags()
	server.Run(flags)
}
