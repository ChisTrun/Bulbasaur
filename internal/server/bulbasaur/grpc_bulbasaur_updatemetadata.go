package bulbasaur

import (
	bulbasaur "bulbasaur/api"
	"context"

	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *bulbasaurServer) UpdateMetadata(ctx context.Context, request *bulbasaur.UpdateMetadataRequest) (*emptypb.Empty, error) {
	if err := s.feature.UserFeature.UpdateMetadata(ctx, request); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
