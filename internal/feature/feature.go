package feature

import (
	"bulbasaur/internal/feature/user"
	"bulbasaur/internal/google"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/services/redis"
	"bulbasaur/internal/services/signer"
	"bulbasaur/package/config"
	"bulbasaur/package/ent"
)

type Feature struct {
	UserFeature user.UserFeature
}

func NewFeature(cfg *config.Config, ent *ent.Client, repo *repositories.Repository, signer signer.Signer, google google.Google, redis redis.Redis) *Feature {
	return &Feature{
		UserFeature: user.NewUserFeature(cfg, ent, repo, signer, google, redis),
	}
}
