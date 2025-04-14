package venusaur

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/feature"
)

func NewServer(feature *feature.Feature) bulbasaur.VenusaurServer {
	return &venusaurServer{
		Feature: feature,
	}
}

type venusaurServer struct {
	bulbasaur.UnimplementedVenusaurServer
	Feature *feature.Feature
}
