package user

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/utils/hash"
	"bulbasaur/internal/utils/tx"
	"bulbasaur/pkg/ent"
	"bulbasaur/pkg/ent/google"
	"bulbasaur/pkg/ent/local"
	"bulbasaur/pkg/ent/user"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
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
		SetBalance(float64(100)).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	err = tx.Client().TransactionHistory.Create().
		SetUserID(user.ID).
		SetAmount(float64(100)).
		SetNote("Gift").
		Exec(ctx)
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

	if metadata.AvatarPath != nil && strings.HasPrefix(*metadata.AvatarPath, "data:image/") {
		uploadedUrl, err := uploadAvatar(ctx, *metadata.AvatarPath, existingUser.ID)
		if err != nil {
			return fmt.Errorf("failed to upload avatar: %w", err)
		}

		if existingUser.Metadata != nil && existingUser.Metadata.AvatarPath != nil {
			old := *existingUser.Metadata.AvatarPath
			defaultPrefix := "https://skillsharp-api.icu/storage/image?key=upload/image/default"
			if !strings.HasPrefix(old, defaultPrefix) {
				go deleteOldAvatar(ctx, old)
			}
		}

		metadata.AvatarPath = &uploadedUrl
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
		SetBalance(float64(100)).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	err = tx.Client().TransactionHistory.Create().
		SetUserID(user.ID).
		SetAmount(float64(100)).
		SetNote("Gift").
		Exec(ctx)
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

func uploadAvatar(ctx context.Context, base64Image string, userID uint64) (string, error) {
	if !strings.HasPrefix(base64Image, "data:image/") {
		return "", fmt.Errorf("invalid image format")
	}

	parts := strings.Split(base64Image, ",")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid base64 image")
	}
	mimeMatches := regexp.MustCompile(`data:(.*);base64`).FindStringSubmatch(parts[0])
	if len(mimeMatches) < 2 || !strings.HasPrefix(mimeMatches[1], "image/") {
		return "", fmt.Errorf("unsupported mime type")
	}

	mimeType := mimeMatches[1]
	buffer, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	if len(buffer) > 2*1024*1024 {
		return "", fmt.Errorf("image too large (max 2MB)")
	}

	now := time.Now()
	ext := strings.Split(mimeType, "/")[1]
	filename := fmt.Sprintf("avatar_%d_%s.%s", userID, now.Format("2006-01-02T15-04-05.000"), ext)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("serviceName", "upload")
	_ = writer.WriteField("prefix", "avatar")
	_ = writer.WriteField("Content-Type", mimeType)

	part, _ := writer.CreateFormFile("file", filename)
	_, _ = part.Write(buffer)
	writer.Close()

	fmt.Printf("Uploading avatar for user %d: %s\n", userID, filename)
	fmt.Printf("Avatar size: %d bytes\n", len(buffer))
	fmt.Printf("Avatar MIME type: %s\n", mimeType)
	fmt.Printf("Avatar upload time: %s\n", now.Format(time.RFC3339))
	fmt.Printf("Avatar upload prefix: %s\n", "avatar")
	fmt.Printf("Avatar upload service: %s\n", "upload")
	fmt.Printf("Header Content-Type: %s\n", writer.FormDataContentType())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://storage:8080/upload", body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 1 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("upload failed: %s", string(respBody))
	}

	var res struct {
		Data struct {
			Result struct {
				Path string `json:"path"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}

	avatarURL := fmt.Sprintf("https://skillsharp-api.icu/storage/image?key=%s", res.Data.Result.Path)
	return avatarURL, nil
}

func deleteOldAvatar(ctx context.Context, avatarPath string) {
	path := strings.TrimPrefix(avatarPath, "https://skillsharp-api.icu/storage/image?key=")
	reqBody := map[string]string{"path": path}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://storage:8080/delete", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 1 * time.Minute}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed to delete old avatar: %v\n", err)
	}
	defer resp.Body.Close()
}

func (r *userRepository) SetPremiumStatus(ctx context.Context, userID uint64, isPremium bool, expires *time.Time) error {
	return r.ent.User.UpdateOneID(userID).
		SetIsPremium(isPremium).
		SetNillablePremiumExpires(expires).
		Exec(ctx)
}
