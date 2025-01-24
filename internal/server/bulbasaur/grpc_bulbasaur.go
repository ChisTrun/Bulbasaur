package bulbasaur

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/feature"
	"bulbasaur/internal/google"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/services/redis"
	"bulbasaur/internal/services/signer"
)

func NewServer(repo *repositories.Repository, signer signer.Signer, google google.Google, redis redis.Redis) bulbasaur.BulbasaurServer {
	return &bulbasaurServer{
		feature: *feature.NewFeature(repo, signer, google, redis),
	}
}

type bulbasaurServer struct {
	bulbasaur.UnimplementedBulbasaurServer
	feature feature.Feature
}
