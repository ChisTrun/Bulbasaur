package venusaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *venusaurServer) FindUserByName(ctx context.Context, request *bulbasaur.FindUserByNameRequest) (*bulbasaur.FindUserByNameResponse, error) {
	return s.Feature.UserFeature.FindUserByName(ctx, request)
}
