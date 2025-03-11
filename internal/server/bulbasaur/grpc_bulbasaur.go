package bulbasaur

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/feature"
)

func NewServer(feature *feature.Feature) bulbasaur.BulbasaurServer {
	return &bulbasaurServer{
		Feature: feature,
	}
}

type bulbasaurServer struct {
	bulbasaur.UnimplementedBulbasaurServer
	Feature *feature.Feature
}
