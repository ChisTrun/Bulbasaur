package ivysaur

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	bulbasaur "bulbasaur/api"
)

func (s *ivysaurServer) ChangePassword(ctx context.Context, request *bulbasaur.ChangePasswordRequest) (*emptypb.Empty, error) {
	if err := s.Feature.UserFeature.ChangePassword(ctx, request); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
