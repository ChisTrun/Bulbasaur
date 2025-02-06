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
	UpdateMetadata(ctx context.Context, request *bulbasaur.UpdateMetadataRequest) error

	Me(ctx context.Context) (*bulbasaur.MeResponse, error)
	ListUser(ctx context.Context, request *bulbasaur.ListUsersRequest) (*bulbasaur.ListUsersResponse, error)
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
		TokenInfo: &bulbasaur.TokenInfo{
			SafeId:       user.SafeID,
			RefreshToken: refreshToken,
			AccessToken:  accessToken,
			Role:         user.Role,
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
				request.GetLocal().GetEmail(),
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
		TokenInfo: &bulbasaur.TokenInfo{
			SafeId:       user.SafeID,
			RefreshToken: accessToken,
			AccessToken:  refreshToken,
			Role:         user.Role,
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
