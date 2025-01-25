package bulbasaur

import (
	bulbasaur "bulbasaur/api"
	"context"
)

func (s *bulbasaurServer) SignIn(ctx context.Context, request *bulbasaur.SignInRequest) (*bulbasaur.SignInResponse, error) {
	return s.feature.UserFeature.SignIn(ctx, request)
}
