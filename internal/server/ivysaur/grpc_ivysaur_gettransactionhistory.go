package ivysaur

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	bulbasaur "bulbasaur/api"
)

func (s *ivysaurServer) GetTransactionHistory(ctx context.Context, request *emptypb.Empty) (*bulbasaur.GetTransactionHistoryResponse, error) {
	return s.Feature.UserFeature.GetTransactionHistory(ctx)
}
