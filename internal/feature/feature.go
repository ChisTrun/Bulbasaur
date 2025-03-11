package feature

import (
	"bulbasaur/internal/feature/user"
	"bulbasaur/internal/google"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/utils/mailer"
	"bulbasaur/internal/utils/redis"
	"bulbasaur/internal/utils/signer"
	config "bulbasaur/pkg/config"
	"bulbasaur/pkg/ent"
)

type Feature struct {
	UserFeature user.UserFeature
}

func NewFeature(cfg *config.Config, ent *ent.Client, repo *repositories.Repository, signer signer.Signer, google google.Google, redis redis.Redis, mailer mailer.Mailer) *Feature {
	return &Feature{
		UserFeature: user.NewUserFeature(cfg, ent, repo, signer, google, redis, mailer),
	}
}
