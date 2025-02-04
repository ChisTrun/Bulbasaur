package bulbasaur

import (
	bulbasaur "bulbasaur/api"
	"context"
)

func (s *bulbasaurServer) ListUsers(ctx context.Context, request *bulbasaur.ListUsersRequest) (*bulbasaur.ListUsersResponse, error) {
	return s.feature.UserFeature.ListUser(ctx, request)
}
