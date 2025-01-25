package bulbasaur

import (
	bulbasaur "bulbasaur/api"
	"context"
)

func (s *bulbasaurServer) SignUp(ctx context.Context, request *bulbasaur.SignUpRequest) (*bulbasaur.SignUpResponse, error) {
	return s.feature.UserFeature.SignUp(ctx, request)
}
