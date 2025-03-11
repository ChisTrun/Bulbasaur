package bulbasaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *bulbasaurServer) SignIn(ctx context.Context, request *bulbasaur.SignInRequest) (*bulbasaur.SignInResponse, error) {
	return s.Feature.UserFeature.SignIn(ctx, request)
}
