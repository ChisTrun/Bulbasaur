package user

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/google"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/utils/extractor"
	"bulbasaur/internal/utils/hash"
	"bulbasaur/internal/utils/mailer"
	"bulbasaur/internal/utils/redis"
	"bulbasaur/internal/utils/signer"
	"bulbasaur/internal/utils/tx"
	"bulbasaur/internal/utils/validation"
	config "bulbasaur/pkg/config"
	"bulbasaur/pkg/ent"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	re "github.com/redis/go-redis/v9"
)

type UserFeature interface {
	SignIn(ctx context.Context, request *bulbasaur.SignInRequest) (*bulbasaur.SignInResponse, error)
	SignUp(ctx context.Context, request *bulbasaur.SignUpRequest) (*bulbasaur.SignUpResponse, error)
	RefreshToken(ctx context.Context, request *bulbasaur.RefreshTokenRequest) (*bulbasaur.RefreshTokenResponse, error)
	UpdateMetadata(ctx context.Context, request *bulbasaur.UpdateMetadataRequest) error

	Me(ctx context.Context) (*bulbasaur.MeResponse, error)
	ListUser(ctx context.Context, request *bulbasaur.ListUsersRequest) (*bulbasaur.ListUsersResponse, error)
	ChangePassword(ctx context.Context, request *bulbasaur.ChangePasswordRequest) error

	EmailVerification(ctx context.Context, request *bulbasaur.EmailVerificationRequest) error
	ResetCodeVerification(ctx context.Context, request *bulbasaur.ResetCodeVerificationRequest) (*bulbasaur.ResetCodeVerificationResponse, error)
	GenerateResetCode(ctx context.Context, request *bulbasaur.GenerateResetCodeRequest) error
	ResetPassword(ctx context.Context, request *bulbasaur.ResetPasswordRequest) error
	FindUserByName(ctx context.Context, request *bulbasaur.FindUserByNameRequest) (*bulbasaur.FindUserByNameResponse, error)
}

type userFeature struct {
	cfg       *config.Config
	repo      *repositories.Repository
	signer    signer.Signer
	ent       *ent.Client
	google    google.Google
	redis     redis.Redis
	mailer    mailer.Mailer
	extractor extractor.Extractor
}

type EmailRequest struct {
	To       string                 `json:"to"`
	Subject  string                 `json:"subject"`
	Template string                 `json:"template"`
	Context  map[string]interface{} `json:"context"`
}

func NewUserFeature(cfg *config.Config, ent *ent.Client, repo *repositories.Repository, signer signer.Signer, google google.Google, redis redis.Redis, mailer mailer.Mailer) UserFeature {
	return &userFeature{
		repo:      repo,
		signer:    signer,
		ent:       ent,
		extractor: extractor.New(),
		google:    google,
		redis:     redis,
		mailer:    mailer,
		cfg:       cfg,
	}
}

func (u *userFeature) SignIn(ctx context.Context, request *bulbasaur.SignInRequest) (*bulbasaur.SignInResponse, error) {
	tenantId := u.extractor.GetTenantID(ctx)
	var (
		user *ent.User
		err  error
	)
	switch request.Credential.(type) {
	case *bulbasaur.SignInRequest_Local_:
		if txErr := tx.WithTransaction(ctx, u.ent, func(ctx context.Context, tx tx.Tx) error {
			user, err = u.repo.UserRepository.GetLocal(ctx, tx, tenantId, request.GetLocal().GetUsername(), request.GetLocal().GetPassword())
			return err
		}); txErr != nil {
			return nil, txErr
		}
	case *bulbasaur.SignInRequest_Google_:
		email, _, _, ok, err := u.google.Verify(ctx, tenantId, request.GetGoogle().GetCredential())
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("google token is invalid or expired")
		}
		if txErr := tx.WithTransaction(ctx, u.ent, func(ctx context.Context, tx tx.Tx) error {
			user, err = u.repo.UserRepository.GetGoogle(ctx, tx, tenantId, email)
			return err
		}); txErr != nil {
			return nil, txErr
		}
	default:
		return nil, fmt.Errorf("credential type is not supported")
	}

	if u.signer == nil {
		return nil, fmt.Errorf("signer is nil")
	}

	if user == nil {
		return nil, fmt.Errorf("user is nil")
	}

	accessToken, err := u.signer.CreateToken(user.ID, user.SafeID, user.Role, bulbasaur.TokenType_TOKEN_TYPE_ACCESS_TOKEN)
	if err != nil {
		return nil, err
	}

	refreshToken, err := u.signer.CreateToken(user.ID, user.SafeID, user.Role, bulbasaur.TokenType_TOKEN_TYPE_REFRESH_TOKEN)
	if err != nil {
		return nil, err
	}

	u.redis.Set(ctx, fmt.Sprintf("%v-at", user.SafeID), accessToken, time.Minute*time.Duration(u.cfg.Auth.AccessExp))
	u.redis.Set(ctx, fmt.Sprintf("%v-rt", user.SafeID), refreshToken, time.Minute*time.Duration(u.cfg.Auth.RefreshExp))

	return &bulbasaur.SignInResponse{
		User: &bulbasaur.User{
			Username: user.Edges.Local.Username,
			Email:    user.Email,
			Metadata: user.Metadata,
			Role:     user.Role,
			Id:       user.ID,
		},
		TokenInfo: &bulbasaur.TokenInfo{
			SafeId:       user.SafeID,
			RefreshToken: refreshToken,
			AccessToken:  accessToken,
			Role:         user.Role,
			UserId:       user.ID,
		},
	}, nil
}

func (u *userFeature) SignUp(ctx context.Context, request *bulbasaur.SignUpRequest) (*bulbasaur.SignUpResponse, error) {
	tenantId := u.extractor.GetTenantID(ctx)
	var (
		user *ent.User
		err  error
	)
	switch request.Credential.(type) {
	case *bulbasaur.SignUpRequest_Local_:
		otpKey := fmt.Sprintf("otp:%s", request.GetLocal().GetEmail())
		storedOtp, err := u.redis.Get(ctx, otpKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get OTP from Redis: %w", err)
		}

		if storedOtp != request.GetLocal().GetOtp() {
			return nil, fmt.Errorf("invalid OTP")
		}

		if err := validation.ValidatePassword(request.GetLocal().GetPassword()); err != nil {
			return nil, err
		}

		if txErr := tx.WithTransaction(ctx, u.ent, func(ctx context.Context, tx tx.Tx) error {
			user, err = u.repo.UserRepository.CreateLocal(ctx, tx, tenantId,
				request.GetLocal().GetUsername(),
				request.GetLocal().GetPassword(),
				request.GetLocal().GetConfirmPassword(),
				request.GetLocal().GetEmail(),
				request.GetMetadata(),
				request.GetRole(),
			)
			return err
		}); txErr != nil {
			return nil, txErr
		}

		_ = u.redis.Delete(ctx, otpKey)
	case *bulbasaur.SignUpRequest_Google_:
		email, fullname, avatarPath, ok, err := u.google.Verify(ctx, tenantId, request.GetGoogle().GetCredential())
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("google token is invalid or expired")
		}
		if available, err := u.google.IsGoogleAvailable(ctx, tenantId, email); err != nil {
			return nil, err
		} else if !available {
			return nil, fmt.Errorf("google account is exist")
		}

		if txErr := tx.WithTransaction(ctx, u.ent, func(ctx context.Context, tx tx.Tx) error {
			user, err = u.repo.UserRepository.CreateGoogle(ctx, tx, tenantId, email, fullname, avatarPath, request.GetRole())
			return err
		}); txErr != nil {
			return nil, txErr
		}
	default:
		return nil, fmt.Errorf("credential type is not supported")
	}

	if u.signer == nil {
		return nil, fmt.Errorf("signer is nil")
	}

	if user == nil {
		return nil, fmt.Errorf("user is nil")
	}

	accessToken, err := u.signer.CreateToken(user.ID, user.SafeID, user.Role, bulbasaur.TokenType_TOKEN_TYPE_ACCESS_TOKEN)
	if err != nil {
		return nil, err
	}

	refreshToken, err := u.signer.CreateToken(user.ID, user.SafeID, user.Role, bulbasaur.TokenType_TOKEN_TYPE_REFRESH_TOKEN)
	if err != nil {
		return nil, err
	}

	u.redis.Set(ctx, fmt.Sprintf("%v-at", user.SafeID), accessToken, time.Minute*time.Duration(u.cfg.Auth.AccessExp))
	u.redis.Set(ctx, fmt.Sprintf("%v-rt", user.SafeID), refreshToken, time.Minute*time.Duration(u.cfg.Auth.RefreshExp))

	return &bulbasaur.SignUpResponse{
		User: &bulbasaur.User{
			Username: user.Edges.Local.Username,
			Email:    user.Email,
			Metadata: user.Metadata,
			Role:     user.Role,
			Id:       user.ID,
		},
		TokenInfo: &bulbasaur.TokenInfo{
			SafeId:       user.SafeID,
			RefreshToken: refreshToken,
			AccessToken:  accessToken,
			Role:         user.Role,
			UserId:       user.ID,
		},
	}, nil
}

func (u *userFeature) RefreshToken(ctx context.Context, request *bulbasaur.RefreshTokenRequest) (*bulbasaur.RefreshTokenResponse, error) {
	claims, err := u.signer.VerifyToken(request.GetTokenInfo().GetRefreshToken(), bulbasaur.TokenType_TOKEN_TYPE_REFRESH_TOKEN)
	if err != nil {
		return nil, err
	}

	if !u.redis.Check(ctx, fmt.Sprintf("%v-rt", claims["safe_id"]), request.GetTokenInfo().GetRefreshToken()) {
		return nil, fmt.Errorf("refresh token is invalid or expired")
	}

	user, err := u.repo.UserRepository.GetUserBySafeID(ctx, claims["safe_id"].(string))
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	accessToken, err := u.signer.CreateToken(user.ID, user.SafeID, user.Role, bulbasaur.TokenType_TOKEN_TYPE_ACCESS_TOKEN)
	if err != nil {
		return nil, err
	}

	refreshToken, err := u.signer.CreateToken(user.ID, user.SafeID, user.Role, bulbasaur.TokenType_TOKEN_TYPE_REFRESH_TOKEN)
	if err != nil {
		return nil, err
	}

	u.redis.Set(ctx, fmt.Sprintf("%v-at", claims["safe_id"]), accessToken, time.Minute*time.Duration(u.cfg.Auth.AccessExp))
	u.redis.Set(ctx, fmt.Sprintf("%v-rt", claims["safe_id"]), refreshToken, time.Minute*time.Duration(u.cfg.Auth.RefreshExp))

	return &bulbasaur.RefreshTokenResponse{
		TokenInfo: &bulbasaur.TokenInfo{
			SafeId:       user.SafeID,
			RefreshToken: refreshToken,
			AccessToken:  accessToken,
			Role:         user.Role,
			UserId:       user.ID,
		},
	}, nil
}

func (u *userFeature) UpdateMetadata(ctx context.Context, request *bulbasaur.UpdateMetadataRequest) error {
	userId, err := u.extractor.GetUserID(ctx)
	if err != nil {
		return err
	}

	return tx.WithTransaction(ctx, u.ent, func(ctx context.Context, tx tx.Tx) error {
		return u.repo.UserRepository.UpdateMetadata(ctx, tx, uint64(userId), request.GetMetadata())
	})
}

func (u *userFeature) Me(ctx context.Context) (*bulbasaur.MeResponse, error) {
	safeId, ok := u.extractor.GetSafeID(ctx)
	if !ok {
		return nil, fmt.Errorf("safe id not found")
	}

	user, err := u.repo.UserRepository.GetUserBySafeID(ctx, safeId)
	if err != nil {
		return nil, err
	}

	mssUser := &bulbasaur.User{
		Email:    user.Email,
		Metadata: user.Metadata,
		Role:     user.Role,
		Id:       user.ID,
	}

	if user.Edges.Local != nil {
		mssUser.Username = user.Edges.Local.Username
	}

	return &bulbasaur.MeResponse{
		User: mssUser,
	}, nil
}

func (u *userFeature) ListUser(ctx context.Context, request *bulbasaur.ListUsersRequest) (*bulbasaur.ListUsersResponse, error) {
	entUsers, err := u.repo.UserRepository.List(ctx, request.GetUserIds())
	if err != nil {
		return nil, err
	}

	users := []*bulbasaur.User{}
	for _, entUser := range entUsers {
		mss := &bulbasaur.User{
			Email:    entUser.Email,
			Metadata: entUser.Metadata,
			Role:     entUser.Role,
		}
		if entUser.Edges.Local != nil {
			mss.Username = entUser.Edges.Local.Username
		}
		users = append(users, mss)
	}

	return &bulbasaur.ListUsersResponse{
		Users: users,
	}, nil
}

func (u *userFeature) EmailVerification(ctx context.Context, request *bulbasaur.EmailVerificationRequest) error {
	email := request.GetEmail()

	err := tx.WithTransaction(ctx, u.ent, func(ctx context.Context, tx tx.Tx) error {
		exists, err := u.repo.UserRepository.IsEmailExists(ctx, tx, email)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("email already exists")
		}

		return nil
	})

	if err != nil {
		return err
	}

	if !validation.IsValidEmail(email) {
		return fmt.Errorf("invalid email format")
	}

	otpKey := fmt.Sprintf("otp:%s", email)
	cooldownKey := fmt.Sprintf("otpCooldown:%s", email)

	cooldown, err := u.redis.Get(ctx, cooldownKey)
	if err != nil && err != re.Nil {
		return fmt.Errorf("failed to check OTP cooldown: %v", err)
	}
	if cooldown != "" {
		return fmt.Errorf("too many request, please try again later")
	}

	// Generate 6-digit OTP
	otp := fmt.Sprintf("%06d", rand.Intn(1000000))

	// expire 5m
	u.redis.Set(ctx, otpKey, otp, 5*time.Minute)

	// cooldown 30s
	u.redis.Set(ctx, cooldownKey, "1", 30*time.Second)

	emailReq := mailer.EmailRequest{
		Email: email,
		Type:  "otp",
		Data: map[string]interface{}{
			"otp":    otp,
			"expiry": "5 minutes",
		},
	}

	err = u.mailer.SendEmail(ctx, emailReq)
	if err != nil {
		return fmt.Errorf("failed to send OTP email: %w", err)
	}

	fmt.Printf("OTP %s sent to %s\n", otp, email)
	return nil
}

func (u *userFeature) ResetCodeVerification(ctx context.Context, request *bulbasaur.ResetCodeVerificationRequest) (*bulbasaur.ResetCodeVerificationResponse, error) {
	resetCode := request.GetResetCode()
	resetKey := fmt.Sprintf("password-reset:%s", resetCode)

	email, err := u.redis.Get(ctx, resetKey)
	if err != nil {
		return nil, fmt.Errorf("invalid reset code: %w", err)
	}

	// if somehow the email is empty but no error
	if email == "" {
		return nil, fmt.Errorf("invalid reset code")
	}

	return &bulbasaur.ResetCodeVerificationResponse{
		Email: email,
	}, nil
}

func generateRandomCode(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := crand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate reset code: %w", err)
	}
	return hex.EncodeToString(bytes)[:length], nil
}

func (u *userFeature) GenerateResetCode(ctx context.Context, request *bulbasaur.GenerateResetCodeRequest) error {
	email := request.GetEmail()

	resetCode, err := generateRandomCode(16)
	if err != nil {
		return fmt.Errorf("failed to generate reset code: %w", err)
	}

	resetLink := fmt.Sprintf("%s%s?key=%s", u.cfg.Frontend.Url, u.cfg.Frontend.ResetPasswordEndpoint, resetCode)

	// expire 1d
	resetKey := fmt.Sprintf("password-reset:%s", resetCode)
	if _, err := u.redis.Set(ctx, resetKey, email, 24*time.Hour); err != nil {
		return fmt.Errorf("failed to store reset code in Redis: %w", err)
	}

	emailReq := mailer.EmailRequest{
		Email: email,
		Type:  "reset_password",
		Data: map[string]interface{}{
			"resetLink": resetLink,
			"expiry":    "5 minutes",
		},
	}

	err = u.mailer.SendEmail(ctx, emailReq)
	if err != nil {
		return fmt.Errorf("failed to send reset email: %w", err)
	}

	fmt.Printf("Reset link %s sent to %s\n", resetLink, email)
	return nil
}

func (u *userFeature) ResetPassword(ctx context.Context, request *bulbasaur.ResetPasswordRequest) error {
	tenantId := u.extractor.GetTenantID(ctx)

	storedEmail, err := u.redis.Get(ctx, fmt.Sprintf("password-reset:%s", request.GetResetCode()))
	if err != nil {
		return fmt.Errorf("invalid or expired reset code")
	}

	if storedEmail != request.Email {
		return fmt.Errorf("invalid email provided for password reset")
	}

	if txErr := tx.WithTransaction(ctx, u.ent, func(ctx context.Context, tx tx.Tx) error {
		return u.repo.UserRepository.UpdatePassword(ctx, tx, tenantId, request.GetEmail(), request.GetNewPassword())
	}); txErr != nil {
		return fmt.Errorf("failed to update password: %w", txErr)
	}

	err = u.redis.Delete(ctx, fmt.Sprintf("password-reset:%s", request.ResetCode))
	if err != nil {
		return fmt.Errorf("failed to delete reset code: %w", err)
	}

	return nil
}

func (u *userFeature) ChangePassword(ctx context.Context, request *bulbasaur.ChangePasswordRequest) error {
	safeId, ok := u.extractor.GetSafeID(ctx)
	if !ok {
		return fmt.Errorf("safe id not found")
	}

	user, err := u.repo.UserRepository.GetUserBySafeID(ctx, safeId)
	if err != nil {
		return err
	}

	tenantId := u.extractor.GetTenantID(ctx)

	if ok := hash.CheckPasswordHash(hash.CreateInput([]string{tenantId, request.OldPassword}), user.Edges.Local.Password); !ok {
		return fmt.Errorf("incorrect password")
	}

	if request.GetNewPassword() != request.GetConfirmNewPassword() {
		return fmt.Errorf("passwords do not match")
	}

	if err := validation.ValidatePassword(request.GetNewPassword()); err != nil {
		return err
	}

	return tx.WithTransaction(ctx, u.ent, func(ctx context.Context, tx tx.Tx) error {
		return u.repo.UserRepository.UpdatePassword(ctx, tx, tenantId, user.Email, request.GetNewPassword())
	})
}

func (u *userFeature) FindUserByName(ctx context.Context, request *bulbasaur.FindUserByNameRequest) (*bulbasaur.FindUserByNameResponse, error) {
	searchName := request.GetName()

	if searchName == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	users, err := u.repo.UserRepository.GetUserByName(ctx, searchName)
	if err != nil {
		return nil, fmt.Errorf("failed to find users: %w", err)
	}

	var userIDs []uint64
	for _, user := range users {
		userIDs = append(userIDs, uint64(user.ID))
	}

	return &bulbasaur.FindUserByNameResponse{
		Ids: userIDs,
	}, nil
}
