package bulbasaur

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/feature"
	"bulbasaur/internal/google"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/services/redis"
	"bulbasaur/internal/services/signer"
	"bulbasaur/package/config"
	"bulbasaur/package/ent"
)

func NewServer(cfg *config.Config, ent *ent.Client, repo *repositories.Repository, signer signer.Signer, google google.Google, redis redis.Redis) bulbasaur.BulbasaurServer {
	return &bulbasaurServer{
		feature: *feature.NewFeature(cfg, ent, repo, signer, google, redis),
	}
}

type bulbasaurServer struct {
	bulbasaur.UnimplementedBulbasaurServer
	feature feature.Feature
}
