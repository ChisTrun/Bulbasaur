package google

import (
	"bulbasaur/package/config"
	"bulbasaur/package/ent"
	entgoogle "bulbasaur/package/ent/google"
	"context"
	"fmt"
	"time"
)

type Google interface {
	Verify(ctx context.Context, tenantID, credential string) (string, bool, error)
	IsGoogleAvailable(ctx context.Context, tenantID, email string) (bool, error)
}

type google struct {
	clientID string
	jwk      *jwk
	ent      *ent.Client
}

func New(config *config.Config, ent *ent.Client) (Google, error) {
	jwk, err := JWK()
	if err != nil {
		return nil, err
	}

	return &google{
		clientID: config.Google.ClientID,
		jwk:      jwk,
		ent:      ent,
	}, nil
}

func (t google) Verify(ctx context.Context, tenantID, credential string) (string, bool, error) {

	token, err := t.jwk.Parse(ctx, credential)
	if err != nil {
		return "", false, err
	}

	if time.Now().After(token.Expiration()) {
		return "", false, nil
	}

	validAudience := false
	for _, aud := range token.Audience() {
		if t.clientID == aud {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return "", false, nil
	}

	email, found := token.Get("email")
	if !found {
		return "", false, fmt.Errorf("email not found")
	}

	return email.(string), true, nil
}

func (u *google) IsGoogleAvailable(ctx context.Context, tenantID, email string) (bool, error) {
	existed, err := u.ent.Google.Query().
		Where(entgoogle.TenantID(tenantID), entgoogle.Email(email)).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("can not check if google existed")
	}
	return !existed, nil
}
