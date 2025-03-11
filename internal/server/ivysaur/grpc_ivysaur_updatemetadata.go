package ivysaur

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	bulbasaur "bulbasaur/api"
)

func (s *ivysaurServer) UpdateMetadata(ctx context.Context, request *bulbasaur.UpdateMetadataRequest) (*emptypb.Empty, error) {
	if err := s.Feature.UserFeature.UpdateMetadata(ctx, request); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
