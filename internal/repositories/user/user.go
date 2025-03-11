package user

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/utils/hash"
	"bulbasaur/internal/utils/tx"
	"bulbasaur/pkg/ent"
	"bulbasaur/pkg/ent/google"
	"bulbasaur/pkg/ent/local"
	"bulbasaur/pkg/ent/user"
	"context"
	"fmt"

	"github.com/google/uuid"
)

type UserRepository interface {
	GetUserBySafeID(ctx context.Context, safeId string) (*ent.User, error)

	// user local
	CreateLocal(ctx context.Context, tx tx.Tx, tenantId, username, password, confirmPassword, email, fullname, company, country, jobTitle string, role bulbasaur.Role) (*ent.User, error)
	GetLocal(ctx context.Context, tx tx.Tx, email, username, password string) (*ent.User, error)

	// user google
	CreateGoogle(ctx context.Context, tx tx.Tx, tenantId, email, fullname, avatarPath string, role bulbasaur.Role) (*ent.User, error)
	GetGoogle(ctx context.Context, tx tx.Tx, tenantId, email string) (*ent.User, error)

	// general
	UpdateMetadata(ctx context.Context, tx tx.Tx, id uint64, metadata string) error
	List(ctx context.Context, userIds []uint64) ([]*ent.User, error)
	IsEmailExists(ctx context.Context, tx tx.Tx, email string) (bool, error)
	UpdatePassword(ctx context.Context, tx tx.Tx, tenantId, email, newPassword string) error
}

type userRepository struct {
	ent *ent.Client
}

func NewUserRepository(ent *ent.Client) UserRepository {
	return &userRepository{
		ent: ent,
	}
}

func (u *userRepository) GetUserBySafeID(ctx context.Context, safeId string) (*ent.User, error) {
	return u.ent.User.Query().Where(user.SafeID(safeId)).
		WithGoogle().
		WithLocal().
		Only(ctx)
}

func (u *userRepository) CreateLocal(ctx context.Context, tx tx.Tx, tenantId, username, password, confirmPassword, email, fullname, company, country, jobTitle string, role bulbasaur.Role) (*ent.User, error) {
	if password != confirmPassword {
		return nil, fmt.Errorf("passwords do not match")
	}

	hashPass, err := hash.HashPassword(hash.CreateInput([]string{tenantId, password}))
	if err != nil {
		return nil, err
	}
	user, err := tx.Client().User.Create().
		SetTenantID(tenantId).
		SetSafeID(uuid.NewString()).
		SetEmail(email).
		SetRole(role).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	user.Edges.Local, err = tx.Client().Local.Create().
		SetTenantID(tenantId).
		SetUsername(username).
		SetPassword(hashPass).
		SetFullname(fullname).
		SetCompany(company).
		SetCountry(country).
		SetJobTitle(jobTitle).
		SetAvatarPath("https://sipr.mojokertokab.go.id/images/avatar/no-image.jpg").
		SetUserID(user.ID).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return user, nil
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

	if ok := hash.CheckPasswordHash(hash.CreateInput([]string{tenantId, password}), user.Edges.Local.Password); !ok {
		return nil, fmt.Errorf("incorrect password")
	}

	return user, nil
}

func (u *userRepository) UpdateMetadata(ctx context.Context, tx tx.Tx, id uint64, metadata string) error {
	return tx.Client().User.UpdateOneID(id).SetMetadata(metadata).Exec(ctx)
}

func (u *userRepository) CreateGoogle(ctx context.Context, tx tx.Tx, tenantId, email, fullname, avatarPath string, role bulbasaur.Role) (*ent.User, error) {

	user, err := tx.Client().User.Create().
		SetTenantID(tenantId).
		SetSafeID(uuid.NewString()).
		SetRole(role).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	user.Edges.Google, err = tx.Client().Google.Create().
		SetTenantID(tenantId).
		SetEmail(email).
		SetUserID(user.ID).
		SetFullname(fullname).
		SetAvatarPath(avatarPath).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (u *userRepository) GetGoogle(ctx context.Context, tx tx.Tx, tenantId, email string) (*ent.User, error) {
	user, err := tx.Client().User.Query().
		Where(
			user.TenantID(tenantId),
			user.HasGoogleWith(
				google.TenantID(tenantId),
				google.Email(email),
			),
		).
		WithGoogle().
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (u *userRepository) List(ctx context.Context, userIds []uint64) ([]*ent.User, error) {
	return u.ent.User.Query().Where(user.IDIn(userIds...)).All(ctx)
}

func (u *userRepository) IsEmailExists(ctx context.Context, tx tx.Tx, email string) (bool, error) {
	count, err := tx.Client().User.Query().
		Where(
			user.Email(email),
		).
		Count(ctx)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (u *userRepository) UpdatePassword(ctx context.Context, tx tx.Tx, tenantId, email, newPassword string) error {
	hashPass, err := hash.HashPassword(hash.CreateInput([]string{tenantId, newPassword}))
	if err != nil {
		return err
	}

	userRecord, err := tx.Client().User.Query().
		Where(user.Email(email)).
		WithLocal().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if userRecord.Edges.Local == nil {
		return fmt.Errorf("password update not allowed for non-local users")
	}

	err = tx.Client().Local.UpdateOneID(userRecord.Edges.Local.ID).
		SetPassword(hashPass).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}
