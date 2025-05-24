package venusaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *venusaurServer) IncreaseBalance(ctx context.Context, request *bulbasaur.IncreaseBalanceRequest) (*bulbasaur.IncreaseBalanceResponse, error) {
	return s.Feature.UserFeature.IncreaseBalance(ctx, request)
}
