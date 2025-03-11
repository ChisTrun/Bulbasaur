package ivysaur

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/feature"
)

func NewServer(feature *feature.Feature) bulbasaur.IvysaurServer {
	return &ivysaurServer{
		Feature: feature,
	}
}

type ivysaurServer struct {
	bulbasaur.UnimplementedIvysaurServer
	Feature *feature.Feature
}
