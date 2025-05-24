package ivysaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *ivysaurServer) SetPremium(ctx context.Context, request *bulbasaur.SetPremiumRequest) (*bulbasaur.SetPremiumResponse, error) {
	return s.Feature.UserFeature.SetPremium(ctx, request)
}
