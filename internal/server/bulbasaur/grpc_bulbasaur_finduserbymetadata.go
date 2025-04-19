package bulbasaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *bulbasaurServer) FindUserByMetadata(ctx context.Context, request *bulbasaur.FindUserByMetadataRequest) (*bulbasaur.FindUserByMetadataResponse, error) {
	return s.Feature.UserFeature.FindUserByMetadata(ctx, request)
}
