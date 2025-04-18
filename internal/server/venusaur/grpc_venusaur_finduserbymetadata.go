package venusaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *venusaurServer) FindUserByMetadata(ctx context.Context, request *bulbasaur.FindUserByMetadataRequest) (*bulbasaur.FindUserByMetadataResponse, error) {
	return s.Feature.UserFeature.FindUserByMetadata(ctx, request)
}
