// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.4.0
// - protoc             v5.27.1
// source: api/bulbasaur.proto

package go_pattern

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.62.0 or later.
const _ = grpc.SupportPackageIsVersion8

const (
	Bulbasaur_SignUp_FullMethodName = "/go_pattern.Bulbasaur/SignUp"
	Bulbasaur_SignIn_FullMethodName = "/go_pattern.Bulbasaur/SignIn"
)

// BulbasaurClient is the client API for Bulbasaur service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type BulbasaurClient interface {
	SignUp(ctx context.Context, in *SignUpRequest, opts ...grpc.CallOption) (*SignUpResponse, error)
	SignIn(ctx context.Context, in *SignInRequest, opts ...grpc.CallOption) (*SignInResponse, error)
}

type bulbasaurClient struct {
	cc grpc.ClientConnInterface
}

func NewBulbasaurClient(cc grpc.ClientConnInterface) BulbasaurClient {
	return &bulbasaurClient{cc}
}

func (c *bulbasaurClient) SignUp(ctx context.Context, in *SignUpRequest, opts ...grpc.CallOption) (*SignUpResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SignUpResponse)
	err := c.cc.Invoke(ctx, Bulbasaur_SignUp_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bulbasaurClient) SignIn(ctx context.Context, in *SignInRequest, opts ...grpc.CallOption) (*SignInResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SignInResponse)
	err := c.cc.Invoke(ctx, Bulbasaur_SignIn_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BulbasaurServer is the server API for Bulbasaur service.
// All implementations must embed UnimplementedBulbasaurServer
// for forward compatibility
type BulbasaurServer interface {
	SignUp(context.Context, *SignUpRequest) (*SignUpResponse, error)
	SignIn(context.Context, *SignInRequest) (*SignInResponse, error)
	mustEmbedUnimplementedBulbasaurServer()
}

// UnimplementedBulbasaurServer must be embedded to have forward compatible implementations.
type UnimplementedBulbasaurServer struct {
}

func (UnimplementedBulbasaurServer) SignUp(context.Context, *SignUpRequest) (*SignUpResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignUp not implemented")
}
func (UnimplementedBulbasaurServer) SignIn(context.Context, *SignInRequest) (*SignInResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignIn not implemented")
}
func (UnimplementedBulbasaurServer) mustEmbedUnimplementedBulbasaurServer() {}

// UnsafeBulbasaurServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to BulbasaurServer will
// result in compilation errors.
type UnsafeBulbasaurServer interface {
	mustEmbedUnimplementedBulbasaurServer()
}

func RegisterBulbasaurServer(s grpc.ServiceRegistrar, srv BulbasaurServer) {
	s.RegisterService(&Bulbasaur_ServiceDesc, srv)
}

func _Bulbasaur_SignUp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignUpRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BulbasaurServer).SignUp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Bulbasaur_SignUp_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BulbasaurServer).SignUp(ctx, req.(*SignUpRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bulbasaur_SignIn_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignInRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BulbasaurServer).SignIn(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Bulbasaur_SignIn_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BulbasaurServer).SignIn(ctx, req.(*SignInRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Bulbasaur_ServiceDesc is the grpc.ServiceDesc for Bulbasaur service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Bulbasaur_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "go_pattern.Bulbasaur",
	HandlerType: (*BulbasaurServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignUp",
			Handler:    _Bulbasaur_SignUp_Handler,
		},
		{
			MethodName: "SignIn",
			Handler:    _Bulbasaur_SignIn_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/bulbasaur.proto",
}