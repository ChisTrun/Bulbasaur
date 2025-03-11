package ivysaur

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	bulbasaur "bulbasaur/api"
)

func (s *ivysaurServer) Me(ctx context.Context, request *emptypb.Empty) (*bulbasaur.MeResponse, error) {
	return s.Feature.UserFeature.Me(ctx)
}
