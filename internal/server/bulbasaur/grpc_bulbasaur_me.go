package bulbasaur

import (
	bulbasaur "bulbasaur/api"
	"context"

	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *bulbasaurServer) Me(ctx context.Context, _ *emptypb.Empty) (*bulbasaur.MeResponse, error) {
	return s.feature.UserFeature.Me(ctx)
}
