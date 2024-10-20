package server

import (
	pb0 "bulbasaur/api"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/server/bulbasaur"
	"bulbasaur/internal/services/signer"
	"bulbasaur/package/config"
	"bulbasaur/package/ent"
	"context"
	"fmt"
	"log"
	"net"

	_ "github.com/go-sql-driver/mysql"
	"google.golang.org/grpc"
)

func Serve(cfg *config.Config) {
	client, err := ent.Open("mysql", fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?parseTime=True", cfg.Database.Username, cfg.Database.Password, cfg.Database.Host, cfg.Database.Port, cfg.Database.Name))
	if err != nil {
		log.Fatalf("failed opening connection to mysql: %v", err)
	}
	defer client.Close()
	// Run the auto migration tool.
	if err := client.Schema.Create(context.Background()); err != nil {
		log.Fatalf("failed creating schema resources: %v", err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", cfg.Server.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	repo := repositories.NewRepository(client)
	signer := signer.NewSigner(cfg)

	pb0.RegisterBulbasaurServer(grpcServer, bulbasaur.NewServer(repo, signer))

	log.Printf("server is runing on: %v:%v", cfg.Server.Host, cfg.Server.Port)
	grpcServer.Serve(lis)
}
