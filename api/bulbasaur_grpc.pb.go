// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v6.30.0
// source: bulbasaur/api/bulbasaur.proto

package bulbasaur

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	Bulbasaur_SignUp_FullMethodName                = "/bulbasaur.Bulbasaur/SignUp"
	Bulbasaur_SignIn_FullMethodName                = "/bulbasaur.Bulbasaur/SignIn"
	Bulbasaur_RefreshToken_FullMethodName          = "/bulbasaur.Bulbasaur/RefreshToken"
	Bulbasaur_ListUsers_FullMethodName             = "/bulbasaur.Bulbasaur/ListUsers"
	Bulbasaur_EmailVerification_FullMethodName     = "/bulbasaur.Bulbasaur/EmailVerification"
	Bulbasaur_ResetCodeVerification_FullMethodName = "/bulbasaur.Bulbasaur/ResetCodeVerification"
	Bulbasaur_GenerateResetCode_FullMethodName     = "/bulbasaur.Bulbasaur/GenerateResetCode"
	Bulbasaur_ResetPassword_FullMethodName         = "/bulbasaur.Bulbasaur/ResetPassword"
)

// BulbasaurClient is the client API for Bulbasaur service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type BulbasaurClient interface {
	SignUp(ctx context.Context, in *SignUpRequest, opts ...grpc.CallOption) (*SignUpResponse, error)
	SignIn(ctx context.Context, in *SignInRequest, opts ...grpc.CallOption) (*SignInResponse, error)
	RefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...grpc.CallOption) (*RefreshTokenResponse, error)
	ListUsers(ctx context.Context, in *ListUsersRequest, opts ...grpc.CallOption) (*ListUsersResponse, error)
	EmailVerification(ctx context.Context, in *EmailVerificationRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	ResetCodeVerification(ctx context.Context, in *ResetCodeVerificationRequest, opts ...grpc.CallOption) (*ResetCodeVerificationResponse, error)
	GenerateResetCode(ctx context.Context, in *GenerateResetCodeRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	ResetPassword(ctx context.Context, in *ResetPasswordRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
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

func (c *bulbasaurClient) RefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...grpc.CallOption) (*RefreshTokenResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(RefreshTokenResponse)
	err := c.cc.Invoke(ctx, Bulbasaur_RefreshToken_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bulbasaurClient) ListUsers(ctx context.Context, in *ListUsersRequest, opts ...grpc.CallOption) (*ListUsersResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListUsersResponse)
	err := c.cc.Invoke(ctx, Bulbasaur_ListUsers_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bulbasaurClient) EmailVerification(ctx context.Context, in *EmailVerificationRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, Bulbasaur_EmailVerification_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bulbasaurClient) ResetCodeVerification(ctx context.Context, in *ResetCodeVerificationRequest, opts ...grpc.CallOption) (*ResetCodeVerificationResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ResetCodeVerificationResponse)
	err := c.cc.Invoke(ctx, Bulbasaur_ResetCodeVerification_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bulbasaurClient) GenerateResetCode(ctx context.Context, in *GenerateResetCodeRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, Bulbasaur_GenerateResetCode_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bulbasaurClient) ResetPassword(ctx context.Context, in *ResetPasswordRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, Bulbasaur_ResetPassword_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BulbasaurServer is the server API for Bulbasaur service.
// All implementations must embed UnimplementedBulbasaurServer
// for forward compatibility.
type BulbasaurServer interface {
	SignUp(context.Context, *SignUpRequest) (*SignUpResponse, error)
	SignIn(context.Context, *SignInRequest) (*SignInResponse, error)
	RefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenResponse, error)
	ListUsers(context.Context, *ListUsersRequest) (*ListUsersResponse, error)
	EmailVerification(context.Context, *EmailVerificationRequest) (*emptypb.Empty, error)
	ResetCodeVerification(context.Context, *ResetCodeVerificationRequest) (*ResetCodeVerificationResponse, error)
	GenerateResetCode(context.Context, *GenerateResetCodeRequest) (*emptypb.Empty, error)
	ResetPassword(context.Context, *ResetPasswordRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedBulbasaurServer()
}

// UnimplementedBulbasaurServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedBulbasaurServer struct{}

func (UnimplementedBulbasaurServer) SignUp(context.Context, *SignUpRequest) (*SignUpResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignUp not implemented")
}
func (UnimplementedBulbasaurServer) SignIn(context.Context, *SignInRequest) (*SignInResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignIn not implemented")
}
func (UnimplementedBulbasaurServer) RefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RefreshToken not implemented")
}
func (UnimplementedBulbasaurServer) ListUsers(context.Context, *ListUsersRequest) (*ListUsersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListUsers not implemented")
}
func (UnimplementedBulbasaurServer) EmailVerification(context.Context, *EmailVerificationRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EmailVerification not implemented")
}
func (UnimplementedBulbasaurServer) ResetCodeVerification(context.Context, *ResetCodeVerificationRequest) (*ResetCodeVerificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ResetCodeVerification not implemented")
}
func (UnimplementedBulbasaurServer) GenerateResetCode(context.Context, *GenerateResetCodeRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateResetCode not implemented")
}
func (UnimplementedBulbasaurServer) ResetPassword(context.Context, *ResetPasswordRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ResetPassword not implemented")
}
func (UnimplementedBulbasaurServer) mustEmbedUnimplementedBulbasaurServer() {}
func (UnimplementedBulbasaurServer) testEmbeddedByValue()                   {}

// UnsafeBulbasaurServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to BulbasaurServer will
// result in compilation errors.
type UnsafeBulbasaurServer interface {
	mustEmbedUnimplementedBulbasaurServer()
}

func RegisterBulbasaurServer(s grpc.ServiceRegistrar, srv BulbasaurServer) {
	// If the following call pancis, it indicates UnimplementedBulbasaurServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
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

func _Bulbasaur_RefreshToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RefreshTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BulbasaurServer).RefreshToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Bulbasaur_RefreshToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BulbasaurServer).RefreshToken(ctx, req.(*RefreshTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bulbasaur_ListUsers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListUsersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BulbasaurServer).ListUsers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Bulbasaur_ListUsers_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BulbasaurServer).ListUsers(ctx, req.(*ListUsersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bulbasaur_EmailVerification_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EmailVerificationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BulbasaurServer).EmailVerification(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Bulbasaur_EmailVerification_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BulbasaurServer).EmailVerification(ctx, req.(*EmailVerificationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bulbasaur_ResetCodeVerification_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResetCodeVerificationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BulbasaurServer).ResetCodeVerification(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Bulbasaur_ResetCodeVerification_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BulbasaurServer).ResetCodeVerification(ctx, req.(*ResetCodeVerificationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bulbasaur_GenerateResetCode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateResetCodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BulbasaurServer).GenerateResetCode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Bulbasaur_GenerateResetCode_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BulbasaurServer).GenerateResetCode(ctx, req.(*GenerateResetCodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bulbasaur_ResetPassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResetPasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BulbasaurServer).ResetPassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Bulbasaur_ResetPassword_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BulbasaurServer).ResetPassword(ctx, req.(*ResetPasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Bulbasaur_ServiceDesc is the grpc.ServiceDesc for Bulbasaur service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Bulbasaur_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "bulbasaur.Bulbasaur",
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
		{
			MethodName: "RefreshToken",
			Handler:    _Bulbasaur_RefreshToken_Handler,
		},
		{
			MethodName: "ListUsers",
			Handler:    _Bulbasaur_ListUsers_Handler,
		},
		{
			MethodName: "EmailVerification",
			Handler:    _Bulbasaur_EmailVerification_Handler,
		},
		{
			MethodName: "ResetCodeVerification",
			Handler:    _Bulbasaur_ResetCodeVerification_Handler,
		},
		{
			MethodName: "GenerateResetCode",
			Handler:    _Bulbasaur_GenerateResetCode_Handler,
		},
		{
			MethodName: "ResetPassword",
			Handler:    _Bulbasaur_ResetPassword_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "bulbasaur/api/bulbasaur.proto",
}

const (
	Ivysaur_UpdateMetadata_FullMethodName = "/bulbasaur.Ivysaur/UpdateMetadata"
	Ivysaur_Me_FullMethodName             = "/bulbasaur.Ivysaur/Me"
	Ivysaur_ChangePassword_FullMethodName = "/bulbasaur.Ivysaur/ChangePassword"
	Ivysaur_LogOut_FullMethodName         = "/bulbasaur.Ivysaur/LogOut"
)

// IvysaurClient is the client API for Ivysaur service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IvysaurClient interface {
	UpdateMetadata(ctx context.Context, in *UpdateMetadataRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	Me(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*MeResponse, error)
	ChangePassword(ctx context.Context, in *ChangePasswordRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	LogOut(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type ivysaurClient struct {
	cc grpc.ClientConnInterface
}

func NewIvysaurClient(cc grpc.ClientConnInterface) IvysaurClient {
	return &ivysaurClient{cc}
}

func (c *ivysaurClient) UpdateMetadata(ctx context.Context, in *UpdateMetadataRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, Ivysaur_UpdateMetadata_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *ivysaurClient) Me(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*MeResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(MeResponse)
	err := c.cc.Invoke(ctx, Ivysaur_Me_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *ivysaurClient) ChangePassword(ctx context.Context, in *ChangePasswordRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, Ivysaur_ChangePassword_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *ivysaurClient) LogOut(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, Ivysaur_LogOut_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IvysaurServer is the server API for Ivysaur service.
// All implementations must embed UnimplementedIvysaurServer
// for forward compatibility.
type IvysaurServer interface {
	UpdateMetadata(context.Context, *UpdateMetadataRequest) (*emptypb.Empty, error)
	Me(context.Context, *emptypb.Empty) (*MeResponse, error)
	ChangePassword(context.Context, *ChangePasswordRequest) (*emptypb.Empty, error)
	LogOut(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
	mustEmbedUnimplementedIvysaurServer()
}

// UnimplementedIvysaurServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedIvysaurServer struct{}

func (UnimplementedIvysaurServer) UpdateMetadata(context.Context, *UpdateMetadataRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateMetadata not implemented")
}
func (UnimplementedIvysaurServer) Me(context.Context, *emptypb.Empty) (*MeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Me not implemented")
}
func (UnimplementedIvysaurServer) ChangePassword(context.Context, *ChangePasswordRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChangePassword not implemented")
}
func (UnimplementedIvysaurServer) LogOut(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LogOut not implemented")
}
func (UnimplementedIvysaurServer) mustEmbedUnimplementedIvysaurServer() {}
func (UnimplementedIvysaurServer) testEmbeddedByValue()                 {}

// UnsafeIvysaurServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IvysaurServer will
// result in compilation errors.
type UnsafeIvysaurServer interface {
	mustEmbedUnimplementedIvysaurServer()
}

func RegisterIvysaurServer(s grpc.ServiceRegistrar, srv IvysaurServer) {
	// If the following call pancis, it indicates UnimplementedIvysaurServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Ivysaur_ServiceDesc, srv)
}

func _Ivysaur_UpdateMetadata_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateMetadataRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IvysaurServer).UpdateMetadata(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Ivysaur_UpdateMetadata_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IvysaurServer).UpdateMetadata(ctx, req.(*UpdateMetadataRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Ivysaur_Me_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IvysaurServer).Me(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Ivysaur_Me_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IvysaurServer).Me(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _Ivysaur_ChangePassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChangePasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IvysaurServer).ChangePassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Ivysaur_ChangePassword_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IvysaurServer).ChangePassword(ctx, req.(*ChangePasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Ivysaur_LogOut_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IvysaurServer).LogOut(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Ivysaur_LogOut_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IvysaurServer).LogOut(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

// Ivysaur_ServiceDesc is the grpc.ServiceDesc for Ivysaur service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Ivysaur_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "bulbasaur.Ivysaur",
	HandlerType: (*IvysaurServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "UpdateMetadata",
			Handler:    _Ivysaur_UpdateMetadata_Handler,
		},
		{
			MethodName: "Me",
			Handler:    _Ivysaur_Me_Handler,
		},
		{
			MethodName: "ChangePassword",
			Handler:    _Ivysaur_ChangePassword_Handler,
		},
		{
			MethodName: "LogOut",
			Handler:    _Ivysaur_LogOut_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "bulbasaur/api/bulbasaur.proto",
}

const (
	Venusaur_FindUserByName_FullMethodName = "/bulbasaur.Venusaur/FindUserByName"
)

// VenusaurClient is the client API for Venusaur service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type VenusaurClient interface {
	FindUserByName(ctx context.Context, in *FindUserByNameRequest, opts ...grpc.CallOption) (*FindUserByNameResponse, error)
}

type venusaurClient struct {
	cc grpc.ClientConnInterface
}

func NewVenusaurClient(cc grpc.ClientConnInterface) VenusaurClient {
	return &venusaurClient{cc}
}

func (c *venusaurClient) FindUserByName(ctx context.Context, in *FindUserByNameRequest, opts ...grpc.CallOption) (*FindUserByNameResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(FindUserByNameResponse)
	err := c.cc.Invoke(ctx, Venusaur_FindUserByName_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VenusaurServer is the server API for Venusaur service.
// All implementations must embed UnimplementedVenusaurServer
// for forward compatibility.
type VenusaurServer interface {
	FindUserByName(context.Context, *FindUserByNameRequest) (*FindUserByNameResponse, error)
	mustEmbedUnimplementedVenusaurServer()
}

// UnimplementedVenusaurServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedVenusaurServer struct{}

func (UnimplementedVenusaurServer) FindUserByName(context.Context, *FindUserByNameRequest) (*FindUserByNameResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FindUserByName not implemented")
}
func (UnimplementedVenusaurServer) mustEmbedUnimplementedVenusaurServer() {}
func (UnimplementedVenusaurServer) testEmbeddedByValue()                  {}

// UnsafeVenusaurServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to VenusaurServer will
// result in compilation errors.
type UnsafeVenusaurServer interface {
	mustEmbedUnimplementedVenusaurServer()
}

func RegisterVenusaurServer(s grpc.ServiceRegistrar, srv VenusaurServer) {
	// If the following call pancis, it indicates UnimplementedVenusaurServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Venusaur_ServiceDesc, srv)
}

func _Venusaur_FindUserByName_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FindUserByNameRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VenusaurServer).FindUserByName(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Venusaur_FindUserByName_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VenusaurServer).FindUserByName(ctx, req.(*FindUserByNameRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Venusaur_ServiceDesc is the grpc.ServiceDesc for Venusaur service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Venusaur_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "bulbasaur.Venusaur",
	HandlerType: (*VenusaurServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "FindUserByName",
			Handler:    _Venusaur_FindUserByName_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "bulbasaur/api/bulbasaur.proto",
}
