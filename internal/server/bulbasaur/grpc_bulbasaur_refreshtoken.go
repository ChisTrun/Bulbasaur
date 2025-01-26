package bulbasaur

import (
	bulbasaur "bulbasaur/api"
	"context"
)

func (s *bulbasaurServer) RefreshToken(ctx context.Context, request *bulbasaur.RefreshTokenRequest) (*bulbasaur.RefreshTokenResponse, error) {
	return s.feature.UserFeature.RefreshToken(ctx, request)
}
