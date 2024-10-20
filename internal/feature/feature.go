package feature

import (
	"bulbasaur/internal/feature/user"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/services/signer"
)

type Feature struct {
	UserFeature user.UserFeature
}

func NewFeature(repo *repositories.Repository, signer signer.Signer) *Feature {
	return &Feature{
		UserFeature: user.NewUserFeature(repo, signer),
	}
}
