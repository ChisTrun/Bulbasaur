package bulbasaur

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	bulbasaur "bulbasaur/api"
)

func (s *bulbasaurServer) EmailVerification(ctx context.Context, request *bulbasaur.EmailVerificationRequest) (*emptypb.Empty, error) {
	if err := s.Feature.UserFeature.EmailVerification(ctx, request); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
