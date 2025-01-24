package google

import (
	"context"

	jwkv2 "github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const _googleCerts = `https://www.googleapis.com/oauth2/v3/certs`

type jwk struct {
	c *jwkv2.Cache
}

func JWK() (*jwk, error) {
	c := jwkv2.NewCache(context.Background())
	if err := c.Register(_googleCerts); err != nil {
		return nil, err
	}
	if _, err := c.Refresh(context.Background(), _googleCerts); err != nil {
		return nil, err
	}

	return &jwk{
		c: c,
	}, nil
}

func (j *jwk) Parse(ctx context.Context, credential string) (jwt.Token, error) {
	set, err := j.c.Get(ctx, _googleCerts)
	if err != nil {
		return nil, err
	}

	return jwt.Parse([]byte(credential), jwt.WithKeySet(set))
}
