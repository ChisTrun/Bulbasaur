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
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
)

type UserRepository interface {
	GetUserById(ctx context.Context, id uint64) (*ent.User, error)
	GetUserBySafeID(ctx context.Context, safeId string) (*ent.User, error)
	GetUserByName(ctx context.Context, name string, roles []bulbasaur.Role) ([]*ent.User, error)
	GetUserByMetadata(ctx context.Context, field, value string, roles []bulbasaur.Role) ([]*ent.User, error)

	// user local
	CreateLocal(ctx context.Context, tx tx.Tx, tenantId, username, password, confirmPassword, email string, metadata *bulbasaur.Metadata, role bulbasaur.Role) (*ent.User, error)
	GetLocal(ctx context.Context, tx tx.Tx, email, username, password string) (*ent.User, error)
	GetLocalByEmail(ctx context.Context, tx tx.Tx, tenantId, email, password string) (*ent.User, error)

	// user google
	CreateGoogle(ctx context.Context, tx tx.Tx, tenantId, email, fullname, avatarPath string, role bulbasaur.Role, metadata *bulbasaur.Metadata) (*ent.User, error)
	GetGoogle(ctx context.Context, tx tx.Tx, tenantId, email string) (*ent.User, error)

	// general
	UpdateMetadata(ctx context.Context, tx tx.Tx, id uint64, metadata *bulbasaur.Metadata) error
	List(ctx context.Context, userIds []uint64) ([]*ent.User, error)
	IsEmailExists(ctx context.Context, tx tx.Tx, email string) (bool, error)
	UpdatePassword(ctx context.Context, tx tx.Tx, tenantId, email, newPassword string) error
	mergeMetadata(oldMeta, newMeta *bulbasaur.Metadata) *bulbasaur.Metadata
	SetPremiumStatus(ctx context.Context, userID uint64, isPremium bool, expires *time.Time) error
}

type userRepository struct {
	ent *ent.Client
}

func NewUserRepository(ent *ent.Client) UserRepository {
	return &userRepository{
		ent: ent,
	}
}

func (u *userRepository) GetUserById(ctx context.Context, id uint64) (*ent.User, error) {
	return u.ent.User.Query().Where(user.ID(id)).
		WithGoogle().
		WithLocal().
		Only(ctx)
}

func (u *userRepository) GetUserBySafeID(ctx context.Context, safeId string) (*ent.User, error) {
	return u.ent.User.Query().Where(user.SafeID(safeId)).
		WithGoogle().
		WithLocal().
		Only(ctx)
}

func (u *userRepository) CreateLocal(ctx context.Context, tx tx.Tx, tenantId, username, password, confirmPassword, email string, metadata *bulbasaur.Metadata, role bulbasaur.Role) (*ent.User, error) {
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
		SetMetadata(metadata).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	user.Edges.Local, err = tx.Client().Local.Create().
		SetTenantID(tenantId).
		SetUsername(username).
		SetPassword(hashPass).
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

func (u *userRepository) GetLocalByEmail(ctx context.Context, tx tx.Tx, tenantId, email, password string) (*ent.User, error) {
	user, err := tx.Client().User.Query().
		Where(
			user.TenantID(tenantId),
			user.Or(
				user.Email(email),
				user.HasLocalWith(
					local.Username(email),
				),
			),
			user.HasLocalWith(
				local.TenantID(tenantId),
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

func (u *userRepository) UpdateMetadata(ctx context.Context, tx tx.Tx, id uint64, metadata *bulbasaur.Metadata) error {
	existingUser, err := tx.Client().User.Get(ctx, id)
	if err != nil {
		return err
	}

	merged := u.mergeMetadata(existingUser.Metadata, metadata)
	return tx.Client().User.UpdateOneID(id).SetMetadata(merged).Exec(ctx)
}

func (u *userRepository) CreateGoogle(ctx context.Context, tx tx.Tx, tenantId, email, fullname, avatarPath string, role bulbasaur.Role, metadata *bulbasaur.Metadata) (*ent.User, error) {
	if metadata == nil {
		metadata = &bulbasaur.Metadata{}
	}
	metadata.Fullname = &fullname
	metadata.AvatarPath = &avatarPath

	user, err := tx.Client().User.Create().
		SetTenantID(tenantId).
		SetSafeID(uuid.NewString()).
		SetRole(role).
		SetEmail(email).
		SetMetadata(metadata).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	user.Edges.Google, err = tx.Client().Google.Create().
		SetTenantID(tenantId).
		SetEmail(email).
		SetUserID(user.ID).
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
	return u.ent.User.Query().Where(user.IDIn(userIds...)).WithLocal().All(ctx)
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

func (u *userRepository) GetUserByName(ctx context.Context, name string, roles []bulbasaur.Role) ([]*ent.User, error) {
	predicate := func(s *sql.Selector) {
		s.Where(sql.ExprP("LOWER(JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.fullname'))) LIKE LOWER(?)", "%"+name+"%"))

		if len(roles) > 0 {
			roleValues := make([]interface{}, len(roles))
			for i, role := range roles {
				roleValues[i] = role
			}
			s.Where(sql.In("role", roleValues...))
		}
	}

	users, err := u.ent.User.Query().
		Where().
		Modify(predicate).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to get users by name: %w", err)
	}

	return users, nil
}

func (u *userRepository) GetUserByMetadata(ctx context.Context, field, value string, roles []bulbasaur.Role) ([]*ent.User, error) {
	predicate := func(s *sql.Selector) {
		query := fmt.Sprintf("LOWER(JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.%s'))) LIKE LOWER(?)", field)
		s.Where(sql.ExprP(query, "%"+value+"%"))

		if len(roles) > 0 {
			roleValues := make([]interface{}, len(roles))
			for i, role := range roles {
				roleValues[i] = role
			}
			s.Where(sql.In("role", roleValues...))
		}
	}

	users, err := u.ent.User.Query().
		Where().
		Modify(predicate).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to get users by %s: %w", field, err)
	}

	return users, nil
}

func (u *userRepository) mergeMetadata(oldMeta, newMeta *bulbasaur.Metadata) *bulbasaur.Metadata {
	if oldMeta == nil {
		oldMeta = &bulbasaur.Metadata{}
	}

	if newMeta.Fullname != nil {
		oldMeta.Fullname = newMeta.Fullname
	}
	if newMeta.Company != nil {
		oldMeta.Company = newMeta.Company
	}
	if newMeta.Country != nil {
		oldMeta.Country = newMeta.Country
	}
	if newMeta.JobTitle != nil {
		oldMeta.JobTitle = newMeta.JobTitle
	}
	if newMeta.AvatarPath != nil {
		oldMeta.AvatarPath = newMeta.AvatarPath
	}
	if newMeta.Gender != nil {
		oldMeta.Gender = newMeta.Gender
	}
	if newMeta.Birthday != nil {
		oldMeta.Birthday = newMeta.Birthday
	}
	if newMeta.Summary != nil {
		oldMeta.Summary = newMeta.Summary
	}
	if newMeta.Website != nil {
		oldMeta.Website = newMeta.Website
	}
	if newMeta.LinkedIn != nil {
		oldMeta.LinkedIn = newMeta.LinkedIn
	}
	if newMeta.Education != nil {
		oldMeta.Education = newMeta.Education
	}

	return oldMeta
}

func (r *userRepository) SetPremiumStatus(ctx context.Context, userID uint64, isPremium bool, expires *time.Time) error {
	return r.ent.User.UpdateOneID(userID).
		SetIsPremium(isPremium).
		SetNillablePremiumExpires(expires).
		Exec(ctx)
}
