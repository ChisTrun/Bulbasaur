package ivysaur

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *ivysaurServer) LogOut(ctx context.Context, request *emptypb.Empty) (*emptypb.Empty, error) {
	if err := s.Feature.UserFeature.LogOut(ctx); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
