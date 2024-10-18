package bulbasaur

import (
	bulbasaur "bulbasaur/api"
)

func NewServer() bulbasaur.BulbasaurServer {
	return &bulbasaurServer{}
}

type bulbasaurServer struct {
	bulbasaur.UnimplementedBulbasaurServer
}
