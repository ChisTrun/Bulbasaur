package authz

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/header"
	"bulbasaur/internal/services/extractor"
	"bulbasaur/internal/services/signer"
	"context"
	"errors"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	_bearer        = "Bearer"
	_authorization = "authorization"
)

type authZServer struct {
	extractor extractor.Extractor
	signer    signer.Signer
}

// NewServer creates a new authorization server.
func NewServer(extractor extractor.Extractor, signer signer.Signer) authv3.AuthorizationServer {
	return &authZServer{
		extractor: extractor,
		signer:    signer,
	}
}

// Check implements authorization's Check interface which performs authorization check based on the
// attributes associated with the incoming request.
func (s *authZServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	authorization := req.Attributes.Request.Http.Headers[_authorization]
	// tenantID := req.Attributes.Request.Http.Headers[header.TenantID]
	extracted := strings.Fields(authorization)
	if len(extracted) == 2 && extracted[0] == _bearer {
		claims, err := s.signer.VerifyToken(extracted[1], bulbasaur.TokenType_TOKEN_TYPE_ACCESS_TOKEN)
		if err != nil {
			return buildDeniedResponse(int32(rpc.UNAUTHENTICATED), typev3.StatusCode_Unauthorized), nil
		}
		return &authv3.CheckResponse{
			HttpResponse: &authv3.CheckResponse_OkResponse{
				OkResponse: &authv3.OkHttpResponse{
					Headers: s.createHeaders(extracted[1], claims),
				},
			},
			Status: &status.Status{
				Code: int32(rpc.OK),
			},
		}, nil
	}
	return buildDeniedResponse(int32(rpc.UNAUTHENTICATED), typev3.StatusCode_Unauthorized), nil
}

func buildDeniedResponse(outerCode int32, innerCode typev3.StatusCode) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{
			Code: outerCode,
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{
					Code: innerCode,
				},
			},
		},
	}
}

var (
	errCouldNotParseToken = errors.New("could not parse token")
	errTokenInvalid       = errors.New("invalid token")
	errCacheNotFound      = errors.New("cache token not found")
	errTokenInactive      = errors.New("inactive token")
	errUserNotFound       = errors.New("user not found")
)

// func (s *authZServer) verifyAccessToken(ctx context.Context, accessToken, tenantID string) (*signer.Token, *data.User, error) {
// 	tk, err := s.token.AccessToken().Parse(accessToken)
// 	if err != nil {
// 		logging.Logger(ctx).Error("could not parse token", zap.String("token", accessToken), zap.Error(err))
// 		return nil, nil, errCouldNotParseToken
// 	}
// 	if tk.Valid() != nil {
// 		logging.Logger(ctx).Error("invalid token", zap.String("token", accessToken), zap.Error(tk.Valid()))
// 		return nil, nil, errTokenInvalid
// 	}
// 	//if tk.TenantID != tenantID {
// 	//	logging.Logger(ctx).Error("invalid TenantID", zap.String("TenantID", tk.TenantID))
// 	//	return nil, nil, errTokenInvalid
// 	//}

// 	active, err := s.cache.AccessToken().IsActive(ctx, tk)
// 	if err != nil {
// 		logging.Logger(ctx).Error("could not find token in cache", zap.String("token", accessToken), zap.Error(err))
// 		return nil, nil, errCacheNotFound
// 	}
// 	if !active {
// 		hasAnotherToken, err := s.cache.AccessToken().HasToken(ctx, tk.Subject)
// 		if err == nil && hasAnotherToken {
// 			return nil, nil, errTokenInactive
// 		}
// 		if err != nil {
// 			logging.Logger(ctx).Error("could not find token in cache by safeID", zap.String("token", accessToken), zap.Error(err))
// 		}
// 		return nil, nil, errTokenInvalid
// 	}

// 	u, err := s.cache.User().Get(ctx, tk.Subject)
// 	if err != nil {
// 		logging.Logger(ctx).Error("could not find user in cache", zap.String("UserID", tk.Subject), zap.Error(err))
// 		return nil, nil, errUserNotFound
// 	}

// 	return tk, u, nil
// }

func (s *authZServer) createHeaders(token string, claims jwt.MapClaims) []*corev3.HeaderValueOption {
	headers := []*corev3.HeaderValueOption{
		{
			Append: &wrapperspb.BoolValue{Value: false},
			Header: &corev3.HeaderValue{
				Key:   header.TokenID,
				Value: token,
			},
		},
		{
			Append: &wrapperspb.BoolValue{Value: false},
			Header: &corev3.HeaderValue{
				Key:   header.UserID,
				Value: claims["user_id"].(string),
			},
		},
		{
			Append: &wrapperspb.BoolValue{Value: false},
			Header: &corev3.HeaderValue{
				Key:   header.SafeID,
				Value: claims["safe_id"].(string),
			},
		},
	}
	return headers
}
