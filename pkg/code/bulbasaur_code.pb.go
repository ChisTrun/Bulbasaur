// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v6.30.0
// source: bulbasaur/api/bulbasaur_code.proto

package bulbasaur

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Code int32

const (
	// Google GRPC codes
	// import "google.golang.org/grpc/codes"
	Code_OK                  Code = 0
	Code_CANCELLED           Code = 1
	Code_UNKNOWN             Code = 2
	Code_INVALID_ARGUMENT    Code = 3
	Code_DEADLINE_EXCEEDED   Code = 4
	Code_NOT_FOUND           Code = 5
	Code_ALREADY_EXISTS      Code = 6
	Code_PERMISSION_DENIED   Code = 7
	Code_RESOURCE_EXHAUSTED  Code = 8
	Code_FAILED_PRECONDITION Code = 9
	Code_ABORTED             Code = 10
	Code_OUT_OF_RANGE        Code = 11
	Code_UNIMPLEMENTED       Code = 12
	Code_INTERNAL            Code = 13
	Code_UNAVAILABLE         Code = 14
	Code_DATA_LOSS           Code = 15
	Code_UNAUTHENTICATED     Code = 16
)

// Enum value maps for Code.
var (
	Code_name = map[int32]string{
		0:  "OK",
		1:  "CANCELLED",
		2:  "UNKNOWN",
		3:  "INVALID_ARGUMENT",
		4:  "DEADLINE_EXCEEDED",
		5:  "NOT_FOUND",
		6:  "ALREADY_EXISTS",
		7:  "PERMISSION_DENIED",
		8:  "RESOURCE_EXHAUSTED",
		9:  "FAILED_PRECONDITION",
		10: "ABORTED",
		11: "OUT_OF_RANGE",
		12: "UNIMPLEMENTED",
		13: "INTERNAL",
		14: "UNAVAILABLE",
		15: "DATA_LOSS",
		16: "UNAUTHENTICATED",
	}
	Code_value = map[string]int32{
		"OK":                  0,
		"CANCELLED":           1,
		"UNKNOWN":             2,
		"INVALID_ARGUMENT":    3,
		"DEADLINE_EXCEEDED":   4,
		"NOT_FOUND":           5,
		"ALREADY_EXISTS":      6,
		"PERMISSION_DENIED":   7,
		"RESOURCE_EXHAUSTED":  8,
		"FAILED_PRECONDITION": 9,
		"ABORTED":             10,
		"OUT_OF_RANGE":        11,
		"UNIMPLEMENTED":       12,
		"INTERNAL":            13,
		"UNAVAILABLE":         14,
		"DATA_LOSS":           15,
		"UNAUTHENTICATED":     16,
	}
)

func (x Code) Enum() *Code {
	p := new(Code)
	*p = x
	return p
}

func (x Code) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Code) Descriptor() protoreflect.EnumDescriptor {
	return file_bulbasaur_api_bulbasaur_code_proto_enumTypes[0].Descriptor()
}

func (Code) Type() protoreflect.EnumType {
	return &file_bulbasaur_api_bulbasaur_code_proto_enumTypes[0]
}

func (x Code) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Code.Descriptor instead.
func (Code) EnumDescriptor() ([]byte, []int) {
	return file_bulbasaur_api_bulbasaur_code_proto_rawDescGZIP(), []int{0}
}

var File_bulbasaur_api_bulbasaur_code_proto protoreflect.FileDescriptor

var file_bulbasaur_api_bulbasaur_code_proto_rawDesc = string([]byte{
	0x0a, 0x22, 0x62, 0x75, 0x6c, 0x62, 0x61, 0x73, 0x61, 0x75, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x62, 0x75, 0x6c, 0x62, 0x61, 0x73, 0x61, 0x75, 0x72, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x62, 0x75, 0x6c, 0x62, 0x61, 0x73, 0x61, 0x75, 0x72, 0x2e,
	0x63, 0x6f, 0x64, 0x65, 0x2a, 0xb7, 0x02, 0x0a, 0x04, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x06, 0x0a,
	0x02, 0x4f, 0x4b, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x43, 0x41, 0x4e, 0x43, 0x45, 0x4c, 0x4c,
	0x45, 0x44, 0x10, 0x01, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10,
	0x02, 0x12, 0x14, 0x0a, 0x10, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x5f, 0x41, 0x52, 0x47,
	0x55, 0x4d, 0x45, 0x4e, 0x54, 0x10, 0x03, 0x12, 0x15, 0x0a, 0x11, 0x44, 0x45, 0x41, 0x44, 0x4c,
	0x49, 0x4e, 0x45, 0x5f, 0x45, 0x58, 0x43, 0x45, 0x45, 0x44, 0x45, 0x44, 0x10, 0x04, 0x12, 0x0d,
	0x0a, 0x09, 0x4e, 0x4f, 0x54, 0x5f, 0x46, 0x4f, 0x55, 0x4e, 0x44, 0x10, 0x05, 0x12, 0x12, 0x0a,
	0x0e, 0x41, 0x4c, 0x52, 0x45, 0x41, 0x44, 0x59, 0x5f, 0x45, 0x58, 0x49, 0x53, 0x54, 0x53, 0x10,
	0x06, 0x12, 0x15, 0x0a, 0x11, 0x50, 0x45, 0x52, 0x4d, 0x49, 0x53, 0x53, 0x49, 0x4f, 0x4e, 0x5f,
	0x44, 0x45, 0x4e, 0x49, 0x45, 0x44, 0x10, 0x07, 0x12, 0x16, 0x0a, 0x12, 0x52, 0x45, 0x53, 0x4f,
	0x55, 0x52, 0x43, 0x45, 0x5f, 0x45, 0x58, 0x48, 0x41, 0x55, 0x53, 0x54, 0x45, 0x44, 0x10, 0x08,
	0x12, 0x17, 0x0a, 0x13, 0x46, 0x41, 0x49, 0x4c, 0x45, 0x44, 0x5f, 0x50, 0x52, 0x45, 0x43, 0x4f,
	0x4e, 0x44, 0x49, 0x54, 0x49, 0x4f, 0x4e, 0x10, 0x09, 0x12, 0x0b, 0x0a, 0x07, 0x41, 0x42, 0x4f,
	0x52, 0x54, 0x45, 0x44, 0x10, 0x0a, 0x12, 0x10, 0x0a, 0x0c, 0x4f, 0x55, 0x54, 0x5f, 0x4f, 0x46,
	0x5f, 0x52, 0x41, 0x4e, 0x47, 0x45, 0x10, 0x0b, 0x12, 0x11, 0x0a, 0x0d, 0x55, 0x4e, 0x49, 0x4d,
	0x50, 0x4c, 0x45, 0x4d, 0x45, 0x4e, 0x54, 0x45, 0x44, 0x10, 0x0c, 0x12, 0x0c, 0x0a, 0x08, 0x49,
	0x4e, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x10, 0x0d, 0x12, 0x0f, 0x0a, 0x0b, 0x55, 0x4e, 0x41,
	0x56, 0x41, 0x49, 0x4c, 0x41, 0x42, 0x4c, 0x45, 0x10, 0x0e, 0x12, 0x0d, 0x0a, 0x09, 0x44, 0x41,
	0x54, 0x41, 0x5f, 0x4c, 0x4f, 0x53, 0x53, 0x10, 0x0f, 0x12, 0x13, 0x0a, 0x0f, 0x55, 0x4e, 0x41,
	0x55, 0x54, 0x48, 0x45, 0x4e, 0x54, 0x49, 0x43, 0x41, 0x54, 0x45, 0x44, 0x10, 0x10, 0x42, 0x1e,
	0x5a, 0x1c, 0x62, 0x75, 0x6c, 0x62, 0x61, 0x73, 0x61, 0x75, 0x72, 0x2f, 0x70, 0x6b, 0x67, 0x2f,
	0x63, 0x6f, 0x64, 0x65, 0x3b, 0x62, 0x75, 0x6c, 0x62, 0x61, 0x73, 0x61, 0x75, 0x72, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_bulbasaur_api_bulbasaur_code_proto_rawDescOnce sync.Once
	file_bulbasaur_api_bulbasaur_code_proto_rawDescData []byte
)

func file_bulbasaur_api_bulbasaur_code_proto_rawDescGZIP() []byte {
	file_bulbasaur_api_bulbasaur_code_proto_rawDescOnce.Do(func() {
		file_bulbasaur_api_bulbasaur_code_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_bulbasaur_api_bulbasaur_code_proto_rawDesc), len(file_bulbasaur_api_bulbasaur_code_proto_rawDesc)))
	})
	return file_bulbasaur_api_bulbasaur_code_proto_rawDescData
}

var file_bulbasaur_api_bulbasaur_code_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_bulbasaur_api_bulbasaur_code_proto_goTypes = []any{
	(Code)(0), // 0: bulbasaur.code.Code
}
var file_bulbasaur_api_bulbasaur_code_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_bulbasaur_api_bulbasaur_code_proto_init() }
func file_bulbasaur_api_bulbasaur_code_proto_init() {
	if File_bulbasaur_api_bulbasaur_code_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_bulbasaur_api_bulbasaur_code_proto_rawDesc), len(file_bulbasaur_api_bulbasaur_code_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_bulbasaur_api_bulbasaur_code_proto_goTypes,
		DependencyIndexes: file_bulbasaur_api_bulbasaur_code_proto_depIdxs,
		EnumInfos:         file_bulbasaur_api_bulbasaur_code_proto_enumTypes,
	}.Build()
	File_bulbasaur_api_bulbasaur_code_proto = out.File
	file_bulbasaur_api_bulbasaur_code_proto_goTypes = nil
	file_bulbasaur_api_bulbasaur_code_proto_depIdxs = nil
}
