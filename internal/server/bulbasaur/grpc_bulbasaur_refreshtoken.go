package bulbasaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *bulbasaurServer) RefreshToken(ctx context.Context, request *bulbasaur.RefreshTokenRequest) (*bulbasaur.RefreshTokenResponse, error) {
	return s.Feature.UserFeature.RefreshToken(ctx, request)
}
