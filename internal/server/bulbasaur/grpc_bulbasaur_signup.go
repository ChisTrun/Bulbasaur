package bulbasaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *bulbasaurServer) SignUp(ctx context.Context, request *bulbasaur.SignUpRequest) (*bulbasaur.SignUpResponse, error) {
	return s.Feature.UserFeature.SignUp(ctx, request)
}
