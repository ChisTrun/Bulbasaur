package server

import (
	dbe "bulbasaur/pkg/database/pkg/ent"
	"bulbasaur/pkg/ent"
	"bulbasaur/pkg/ent/migrate"
	mykit "bulbasaur/pkg/mykit/pkg/api"
	"context"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/encoding/protojson"

	pb0 "bulbasaur/api"
	"bulbasaur/internal/feature"
	"bulbasaur/internal/google"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/server/authz"
	"bulbasaur/internal/server/bulbasaur"
	"bulbasaur/internal/server/ivysaur"
	"bulbasaur/internal/utils/extractor"
	"bulbasaur/internal/utils/mailer"
	"bulbasaur/internal/utils/redis"
	"bulbasaur/internal/utils/signer"
	config "bulbasaur/pkg/config"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

func customMetadataAnnotator(ctx context.Context, req *http.Request) metadata.MD {
	md := metadata.MD{}

	// Map tất cả các header có prefix "x-" vào metadata
	for name, values := range req.Header {
		lowerName := strings.ToLower(name)
		if strings.HasPrefix(lowerName, "x-") {
			md.Append(lowerName, values...)
		}
	}

	return md
}

// Serve ...
func Serve(cfg *config.Config) {
	service := newService(cfg, []mykit.Option{}...)
	logger := service.Logger()

	server := service.Server()

	drv, err := dbe.Open("mysql_rum", cfg.GetDatabase())
	ent := ent.NewClient(ent.Driver(drv))
	defer func() {
		if err := ent.Close(); err != nil {
			logger.Fatal("can not close ent client", zap.Error(err))
		}
	}()
	if err != nil {
		logger.Fatal("can not open ent client", zap.Error(err))
	}
	if err = ent.Schema.Create(context.Background(), migrate.WithDropIndex(true)); err != nil {
		logger.Fatal("can not init my database", zap.Error(err))
	}

	repo := repositories.NewRepository(ent)
	signer := signer.NewSigner(cfg)
	mailer := mailer.NewMailer(cfg)

	redis := redis.New(true, cfg)

	google, err := google.New(cfg, ent)
	if err != nil {
		logger.Fatal("failed to create google client: %v", zap.Error(err))
	}

	feature := feature.NewFeature(cfg, ent, repo, signer, google, redis, mailer)

	bulbasaurServer := bulbasaur.NewServer(feature)
	ivysaurServer := ivysaur.NewServer(feature)

	grpcGatewayMux := runtime.NewServeMux(
		runtime.WithMetadata(customMetadataAnnotator),
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: true,
				UseEnumNumbers:  false,
			},
		}),
	)

	service.HttpServeMux().Handle("/bulbasaur/", grpcGatewayMux)
	service.HttpServeMux().Handle("/ivysaur/", grpcGatewayMux)

	err = pb0.RegisterBulbasaurHandlerServer(context.Background(), grpcGatewayMux, bulbasaurServer)
	if err != nil {
		logger.Fatal("can not register http sibel server", zap.Error(err))
	}

	err = pb0.RegisterIvysaurHandlerServer(context.Background(), grpcGatewayMux, ivysaurServer)
	if err != nil {
		logger.Fatal("can not register http sibel server", zap.Error(err))
	}

	pb0.RegisterBulbasaurServer(server, bulbasaurServer)
	pb0.RegisterIvysaurServer(server, ivysaurServer)
	// Register reflection service on gRPC server.
	// Please remove if you it's not necessary for your service
	reflection.Register(server)

	extractor := extractor.New()
	authv3.RegisterAuthorizationServer(server, authz.NewServer(extractor, signer, redis))

	service.Serve()
}
