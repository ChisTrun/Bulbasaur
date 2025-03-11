package bulbasaur

import (
	"context"

	bulbasaur "bulbasaur/api"
)

func (s *bulbasaurServer) ListUsers(ctx context.Context, request *bulbasaur.ListUsersRequest) (*bulbasaur.ListUsersResponse, error) {
	return s.Feature.UserFeature.ListUser(ctx, request)
}
