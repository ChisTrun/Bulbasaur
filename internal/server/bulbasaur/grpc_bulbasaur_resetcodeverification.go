package bulbasaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *bulbasaurServer) ResetCodeVerification(ctx context.Context, request *bulbasaur.ResetCodeVerificationRequest) (*bulbasaur.ResetCodeVerificationResponse, error) {
	return s.Feature.UserFeature.ResetCodeVerification(ctx, request)
}
