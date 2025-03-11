package repositories

import (
	"bulbasaur/internal/repositories/user"
	"bulbasaur/pkg/ent"
)

type Repository struct {
	UserRepository user.UserRepository
}

func NewRepository(ent *ent.Client) *Repository {
	return &Repository{
		UserRepository: user.NewUserRepository(ent),
	}
}
