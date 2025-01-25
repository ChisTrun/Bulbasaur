package authz

import (
	bulbasaur "bulbasaur/api"
	"bulbasaur/internal/header"
	"bulbasaur/internal/services/extractor"
	"bulbasaur/internal/services/redis"
	"bulbasaur/internal/services/signer"
	"context"
	"fmt"
	"log"
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
	redis     redis.Redis
}

// NewServer creates a new authorization server.
func NewServer(extractor extractor.Extractor, signer signer.Signer, redis redis.Redis) authv3.AuthorizationServer {
	return &authZServer{
		extractor: extractor,
		signer:    signer,
		redis:     redis,
	}
}

// Check implements authorization's Check interface which performs authorization check based on the
// attributes associated with the incoming request.
func (s *authZServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	log.Println("start authorization check")
	authorization := req.Attributes.Request.Http.Headers[_authorization]
	// tenantID := req.Attributes.Request.Http.Headers[header.TenantID]
	extracted := strings.Fields(authorization)
	if len(extracted) == 2 && extracted[0] == _bearer {
		log.Println("access token found: ", extracted[1])
		claims, err := s.signer.VerifyToken(extracted[1], bulbasaur.TokenType_TOKEN_TYPE_ACCESS_TOKEN)
		if err != nil {
			log.Println("authorization check failed: ", err)
			return buildDeniedResponse(int32(rpc.UNAUTHENTICATED), typev3.StatusCode_Unauthorized), nil
		}
		isAvailable := s.redis.Check(ctx, fmt.Sprintf("%v-at", claims["safe_id"]), extracted[1])
		if !isAvailable {
			log.Println("authorization check failed: token is not available")
			return buildDeniedResponse(int32(rpc.UNAUTHENTICATED), typev3.StatusCode_Unauthorized), nil
		}
		log.Println("authorization check success")
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
	log.Println("authorization check failed")
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
