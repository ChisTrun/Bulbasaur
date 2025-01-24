package feature

import (
	"bulbasaur/internal/feature/user"
	"bulbasaur/internal/google"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/services/redis"
	"bulbasaur/internal/services/signer"
)

type Feature struct {
	UserFeature user.UserFeature
}

func NewFeature(repo *repositories.Repository, signer signer.Signer, google google.Google, redis redis.Redis) *Feature {
	return &Feature{
		UserFeature: user.NewUserFeature(repo, signer, google, redis),
	}
}
