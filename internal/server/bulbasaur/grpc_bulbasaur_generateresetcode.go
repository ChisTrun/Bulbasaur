package bulbasaur

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	bulbasaur "bulbasaur/api"
)

func (s *bulbasaurServer) GenerateResetCode(ctx context.Context, request *bulbasaur.GenerateResetCodeRequest) (*emptypb.Empty, error) {
	if err := s.Feature.UserFeature.GenerateResetCode(ctx, request); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
