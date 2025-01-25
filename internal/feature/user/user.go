package user

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/google"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/services/extractor"
	"bulbasaur/internal/services/redis"
	"bulbasaur/internal/services/signer"
	"bulbasaur/internal/services/tx"
	"bulbasaur/package/config"
	"bulbasaur/package/ent"
	"context"
	"fmt"
	"time"
)

type UserFeature interface {
	SignIn(ctx context.Context, request *bulbasaur.SignInRequest) (*bulbasaur.SignInResponse, error)
	SignUp(ctx context.Context, request *bulbasaur.SignUpRequest) (*bulbasaur.SignUpResponse, error)
	RefreshToken(ctx context.Context, request *bulbasaur.RefreshTokenRequest) (*bulbasaur.RefreshTokenResponse, error)
}

type userFeature struct {
	cfg       *config.Config
	repo      *repositories.Repository
	signer    signer.Signer
	ent       *ent.Client
	google    google.Google
	redis     redis.Redis
	extractor extractor.Extractor
}

func NewUserFeature(cfg *config.Config, ent *ent.Client, repo *repositories.Repository, signer signer.Signer, google google.Google, redis redis.Redis) UserFeature {
	return &userFeature{
		repo:      repo,
		signer:    signer,
		ent:       ent,
		extractor: extractor.New(),
		google:    google,
		redis:     redis,
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
		email, ok, err := u.google.Verify(ctx, tenantId, request.GetGoogle().GetCredential())
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
	}

	accessToken, err := u.signer.CreateToken(user.ID, user.SafeID, bulbasaur.TokenType_TOKEN_TYPE_ACCESS_TOKEN)
	if err != nil {
		return nil, err
	}

	refreshToken, err := u.signer.CreateToken(user.ID, user.SafeID, bulbasaur.TokenType_TOKEN_TYPE_REFRESH_TOKEN)
	if err != nil {
		return nil, err
	}

	u.redis.Set(ctx, fmt.Sprintf("%v-at", user.SafeID), accessToken, time.Minute*time.Duration(u.cfg.Auth.AccessExp))
	u.redis.Set(ctx, fmt.Sprintf("%v-rt", user.SafeID), refreshToken, time.Minute*time.Duration(u.cfg.Auth.RefreshExp))

	return &bulbasaur.SignInResponse{
		TokenInfo: &bulbasaur.TokenInfo{
			UserId:       user.ID,
			RefreshToken: refreshToken,
			AccessToken:  accessToken,
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
		if txErr := tx.WithTransaction(ctx, u.ent, func(ctx context.Context, tx tx.Tx) error {
			user, err = u.repo.UserRepository.CreateLocal(ctx, tx, tenantId,
				request.GetLocal().GetUsername(),
				request.GetLocal().GetPassword(),
				request.GetLocal().GetConfirmPassword(),
				request.GetRole(),
			)
			return err
		}); txErr != nil {
			return nil, txErr
		}
	case *bulbasaur.SignUpRequest_Google_:
		email, ok, err := u.google.Verify(ctx, tenantId, request.GetGoogle().GetCredential())
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
			user, err = u.repo.UserRepository.CreateGoogle(ctx, tx, tenantId, email, request.GetRole())
			return err
		}); txErr != nil {
			return nil, txErr
		}
	}

	accessToken, err := u.signer.CreateToken(user.ID, user.SafeID, bulbasaur.TokenType_TOKEN_TYPE_ACCESS_TOKEN)
	if err != nil {
		return nil, err
	}

	refreshToken, err := u.signer.CreateToken(user.ID, user.SafeID, bulbasaur.TokenType_TOKEN_TYPE_REFRESH_TOKEN)
	if err != nil {
		return nil, err
	}

	u.redis.Set(ctx, fmt.Sprintf("%v-at", user.SafeID), accessToken, time.Minute*time.Duration(u.cfg.Auth.AccessExp))
	u.redis.Set(ctx, fmt.Sprintf("%v-rt", user.SafeID), refreshToken, time.Minute*time.Duration(u.cfg.Auth.RefreshExp))

	return &bulbasaur.SignUpResponse{
		TokenInfo: &bulbasaur.TokenInfo{
			UserId:       user.ID,
			RefreshToken: accessToken,
			AccessToken:  refreshToken,
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

	accessToken, err := u.signer.CreateToken(uint64(claims["user_id"].(float64)), claims["safe_id"].(string), bulbasaur.TokenType_TOKEN_TYPE_ACCESS_TOKEN)
	if err != nil {
		return nil, err
	}

	refreshToken, err := u.signer.CreateToken(uint64(claims["user_id"].(float64)), claims["safe_id"].(string), bulbasaur.TokenType_TOKEN_TYPE_REFRESH_TOKEN)
	if err != nil {
		return nil, err
	}

	u.redis.Set(ctx, fmt.Sprintf("%v-at", claims["safe_id"]), accessToken, time.Minute*time.Duration(u.cfg.Auth.AccessExp))
	u.redis.Set(ctx, fmt.Sprintf("%v-rt", claims["safe_id"]), refreshToken, time.Minute*time.Duration(u.cfg.Auth.RefreshExp))

	return &bulbasaur.RefreshTokenResponse{
		TokenInfo: &bulbasaur.TokenInfo{
			UserId:       uint64(claims["user_id"].(float64)),
			RefreshToken: accessToken,
			AccessToken:  refreshToken,
		},
	}, nil
}
