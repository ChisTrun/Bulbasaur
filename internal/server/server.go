package server

import (
	pb0 "bulbasaur/api"
	"bulbasaur/internal/google"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/server/authz"
	"bulbasaur/internal/server/bulbasaur"
	"bulbasaur/internal/services/extractor"
	"bulbasaur/internal/services/redis"
	"bulbasaur/internal/services/signer"
	"bulbasaur/package/config"
	"bulbasaur/package/ent"
	"context"
	"fmt"
	"log"
	"net"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

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

	lis, err := net.Listen("tcp", fmt.Sprintf("%v:%d", cfg.Server.Host, cfg.Server.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	repo := repositories.NewRepository(client)
	signer := signer.NewSigner(cfg)

	redis := redis.New(true, cfg)

	google, err := google.New(cfg, client)
	if err != nil {
		log.Fatalf("failed to create google client: %v", err)
	}

	pb0.RegisterBulbasaurServer(grpcServer, bulbasaur.NewServer(cfg, client, repo, signer, google, redis))

	log.Printf("server is runing on: %v:%v", cfg.Server.Host, cfg.Server.Port)

	extractor := extractor.New()
	authv3.RegisterAuthorizationServer(grpcServer, authz.NewServer(extractor, signer, redis))

	grpcServer.Serve(lis)
}
