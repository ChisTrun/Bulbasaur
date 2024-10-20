package user

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/repositories"
	"bulbasaur/internal/services/extractor"
	"bulbasaur/internal/services/signer"
	"bulbasaur/internal/services/tx"
	"bulbasaur/package/ent"
	"context"
)

type UserFeature interface {
	SignIn(ctx context.Context, request *bulbasaur.SignInRequest) (*bulbasaur.SignInResponse, error)
	SignUp(ctx context.Context, request *bulbasaur.SignUpRequest) (*bulbasaur.SignUpResponse, error)
}

type userFeature struct {
	repo      *repositories.Repository
	signer    signer.Signer
	ent       *ent.Client
	extractor extractor.Extractor
}

func NewUserFeature(repo *repositories.Repository, signer signer.Signer) UserFeature {
	return &userFeature{
		repo:      repo,
		signer:    signer,
		ent:       &ent.Client{},
		extractor: extractor.New(),
	}
}

func (u *userFeature) SignIn(ctx context.Context, request *bulbasaur.SignInRequest) (*bulbasaur.SignInResponse, error) {
	return nil, nil
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
				request.GetLocal().GetConfirmPassword())
			return err
		}); txErr != nil {
			return nil, txErr
		}
	}

	accessToken, err := u.signer.CreateToken(user.ID, user.SafeID, bulbasaur.TokenType_TOKEN_TYPE_ACCESS_TOKEN)
	if err != nil {
		return nil, err
	}

	refeshToken, err := u.signer.CreateToken(user.ID, user.SafeID, bulbasaur.TokenType_TOKEN_TYPE_REFESH_TOKEN)
	if err != nil {
		return nil, err
	}

	return &bulbasaur.SignUpResponse{
		TokenInfo: &bulbasaur.TokenInfo{
			UserId:      user.ID,
			RefeshToken: accessToken,
			AccessToken: refeshToken,
		},
	}, nil
}
