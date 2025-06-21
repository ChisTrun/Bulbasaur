package venusaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *venusaurServer) StartTransaction(ctx context.Context, request *bulbasaur.StartTransactionRequest) (*bulbasaur.StartTransactionResponse, error) {
	return s.Feature.UserFeature.StartTransaction(ctx, request)
}
