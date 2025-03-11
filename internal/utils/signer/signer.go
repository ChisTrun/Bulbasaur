package signer

import (
	bulbasaur "bulbasaur/api"
	config "bulbasaur/pkg/config"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Signer interface {
	CreateToken(userId uint64, safeId string, role bulbasaur.Role, tokenType bulbasaur.TokenType) (string, error)
	VerifyToken(token string, tokenType bulbasaur.TokenType) (jwt.MapClaims, error)
}

type signer struct {
	cfg *config.Config
}

func NewSigner(cfg *config.Config) Signer {
	return &signer{
		cfg: cfg,
	}
}

func (s *signer) CreateToken(userId uint64, safeId string, role bulbasaur.Role, tokenType bulbasaur.TokenType) (string, error) {
	secretKey := ""
	expTime := 0
	switch tokenType {
	case bulbasaur.TokenType_TOKEN_TYPE_ACCESS_TOKEN:
		secretKey = s.cfg.Auth.AccessKey
		expTime = int(s.cfg.Auth.AccessExp)
	case bulbasaur.TokenType_TOKEN_TYPE_REFRESH_TOKEN:
		secretKey = s.cfg.Auth.RefreshKey
		expTime = int(s.cfg.Auth.RefreshExp)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"user_id": userId,
			"safe_id": safeId,
			"role":    role,
			"exp":     time.Now().Add(time.Minute * time.Duration(expTime)).Unix(),
		})

	return token.SignedString([]byte(secretKey))
}

func (s *signer) VerifyToken(tokenString string, tokenType bulbasaur.TokenType) (jwt.MapClaims, error) {
	secretKey := ""
	switch tokenType {
	case bulbasaur.TokenType_TOKEN_TYPE_ACCESS_TOKEN:
		secretKey = s.cfg.Auth.AccessKey
	case bulbasaur.TokenType_TOKEN_TYPE_REFRESH_TOKEN:
		secretKey = s.cfg.Auth.RefreshKey
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token")
	}
}
