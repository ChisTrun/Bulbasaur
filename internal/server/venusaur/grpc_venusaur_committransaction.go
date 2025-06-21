package venusaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *venusaurServer) CommitTransaction(ctx context.Context, request *bulbasaur.CommitTransactionRequest) (*bulbasaur.CommitTransactionResponse, error) {
	return s.Feature.UserFeature.CommitTransaction(ctx, request)
}
