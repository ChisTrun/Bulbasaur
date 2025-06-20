package venusaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *venusaurServer) DecreaseBalance(ctx context.Context, request *bulbasaur.DecreaseBalanceRequest) (*bulbasaur.DecreaseBalanceResponse, error) {
	return s.Feature.UserFeature.DecreaseBalance(ctx, request)
}
