package user

import (
	"bulbasaur/internal/services/hash"
	"bulbasaur/internal/services/tx"
	"bulbasaur/package/ent"
	"bulbasaur/package/ent/google"
	"bulbasaur/package/ent/local"
	"bulbasaur/package/ent/user"
	"context"
	"fmt"
)

type UserRepository interface {
	// user local
	CreateLocal(ctx context.Context, tx tx.Tx, tenantId, username, password, confirmPassword string) (*ent.User, error)
	GetLocal(ctx context.Context, tx tx.Tx, tenantId, username, password string) (*ent.User, error)

	// user google
	CreateGoogle(ctx context.Context, tx tx.Tx, tenantId, email string) (*ent.User, error)
	GetGoogle(ctx context.Context, tx tx.Tx, tenantId, email string) (*ent.User, error)

	// general
	UpdateMetadata(ctx context.Context, tx tx.Tx, id uint64, metadata string) error
}

type userRepository struct {
	ent *ent.Client
}

func NewUserRepository(ent *ent.Client) UserRepository {
	return &userRepository{
		ent: ent,
	}
}

func (u *userRepository) CreateLocal(ctx context.Context, tx tx.Tx, tenantId, username, password, confirmPassword string) (*ent.User, error) {
	if password != confirmPassword {
		return nil, fmt.Errorf("passwords do not match")
	}

	hashPass, err := hash.HashPassword(hash.CreateInput([]string{username, tenantId, password}))
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}

	local, err := tx.Client().Local.Create().
		SetTenantID(tenantId).
		SetUsername(username).
		SetPassword(hashPass).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return tx.Client().User.Create().SetLocal(local).SetTenantID(tenantId).Save(ctx)
}

func (u *userRepository) GetLocal(ctx context.Context, tx tx.Tx, tenantId, username, password string) (*ent.User, error) {
	user, err := tx.Client().User.Query().
		Where(
			user.TenantID(tenantId),
			user.HasLocalWith(
				local.TenantID(tenantId),
				local.Username(username),
			),
		).
		WithLocal().
		Only(ctx)
	if err != nil {
		return nil, err
	}

	if ok := hash.CheckPasswordHash(hash.CreateInput([]string{username, tenantId, password}), user.Edges.Local.Password); !ok {
		return nil, fmt.Errorf("incorrect password")
	}

	return user, nil
}

func (u *userRepository) UpdateMetadata(ctx context.Context, tx tx.Tx, id uint64, metadata string) error {
	return tx.Client().User.UpdateOneID(id).SetMetadata(metadata).Exec(ctx)
}

func (u *userRepository) CreateGoogle(ctx context.Context, tx tx.Tx, tenantId, email string) (*ent.User, error) {

	google, err := tx.Client().Google.Create().
		SetTenantID(tenantId).
		SetEmail(email).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return tx.Client().User.Create().SetGoogle(google).SetTenantID(tenantId).Save(ctx)
}

func (u *userRepository) GetGoogle(ctx context.Context, tx tx.Tx, tenantId, email string) (*ent.User, error) {
	user, err := tx.Client().User.Query().
		Where(
			user.TenantID(tenantId),
			user.HasGoogleWith(
				google.TenantID(tenantId),
			),
		).
		WithGoogle().
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return user, nil
}
