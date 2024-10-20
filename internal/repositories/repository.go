package repositories

import (
	"bulbasaur/internal/repositories/user"
	"bulbasaur/package/ent"
)

type Repository struct {
	UserRepository user.UserRepository
}

func NewRepository(ent *ent.Client) *Repository {
	return &Repository{
		UserRepository: user.NewUserRepository(ent),
	}
}
