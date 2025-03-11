package bulbasaur

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	bulbasaur "bulbasaur/api"
)

func (s *bulbasaurServer) ResetPassword(ctx context.Context, request *bulbasaur.ResetPasswordRequest) (*emptypb.Empty, error) {
	if err := s.Feature.UserFeature.ResetPassword(ctx, request); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
