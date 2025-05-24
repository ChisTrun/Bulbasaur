package ivysaur

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	bulbasaur "bulbasaur/api"
)

func (s *ivysaurServer) GetBalance(ctx context.Context, request *emptypb.Empty) (*bulbasaur.GetBalanceResponse, error) {
	return s.Feature.UserFeature.GetBalance(ctx)
}
