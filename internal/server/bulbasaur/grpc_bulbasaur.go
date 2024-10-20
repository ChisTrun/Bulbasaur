package bulbasaur

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/feature"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/services/signer"
)

func NewServer(repo *repositories.Repository, signer signer.Signer) bulbasaur.BulbasaurServer {
	return &bulbasaurServer{
		feature: *feature.NewFeature(repo, signer),
	}
}

type bulbasaurServer struct {
	bulbasaur.UnimplementedBulbasaurServer
	feature feature.Feature
}
