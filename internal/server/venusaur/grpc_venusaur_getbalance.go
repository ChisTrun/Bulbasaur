package venusaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *venusaurServer) GetBalance(ctx context.Context, request *bulbasaur.GetBalanceRequest) (*bulbasaur.GetBalanceResponse, error) {
	return s.Feature.UserFeature.GetBalanceInternal(ctx, request)
}
