// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: bulbasaur/api/bulbasaur_config.proto

package bulbasaur

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on Config with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *Config) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Config with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in ConfigMultiError, or nil if none found.
func (m *Config) ValidateAll() error {
	return m.validate(true)
}

func (m *Config) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if m.GetListener() == nil {
		err := ConfigValidationError{
			field:  "Listener",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetListener()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Listener",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Listener",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetListener()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ConfigValidationError{
				field:  "Listener",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if m.GetLogger() == nil {
		err := ConfigValidationError{
			field:  "Logger",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetLogger()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Logger",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Logger",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetLogger()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ConfigValidationError{
				field:  "Logger",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if m.GetDatabase() == nil {
		err := ConfigValidationError{
			field:  "Database",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetDatabase()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Database",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Database",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetDatabase()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ConfigValidationError{
				field:  "Database",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if m.GetRedis() == nil {
		err := ConfigValidationError{
			field:  "Redis",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetRedis()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Redis",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Redis",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetRedis()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ConfigValidationError{
				field:  "Redis",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if m.GetHttpListener() == nil {
		err := ConfigValidationError{
			field:  "HttpListener",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetHttpListener()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "HttpListener",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "HttpListener",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetHttpListener()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ConfigValidationError{
				field:  "HttpListener",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if m.GetAuth() == nil {
		err := ConfigValidationError{
			field:  "Auth",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetAuth()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Auth",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Auth",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetAuth()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ConfigValidationError{
				field:  "Auth",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if m.GetGoogle() == nil {
		err := ConfigValidationError{
			field:  "Google",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetGoogle()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Google",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Google",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetGoogle()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ConfigValidationError{
				field:  "Google",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if m.GetFrontend() == nil {
		err := ConfigValidationError{
			field:  "Frontend",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetFrontend()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Frontend",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Frontend",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetFrontend()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ConfigValidationError{
				field:  "Frontend",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if m.GetMailer() == nil {
		err := ConfigValidationError{
			field:  "Mailer",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetMailer()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Mailer",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "Mailer",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetMailer()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ConfigValidationError{
				field:  "Mailer",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return ConfigMultiError(errors)
	}

	return nil
}

// ConfigMultiError is an error wrapping multiple validation errors returned by
// Config.ValidateAll() if the designated constraints aren't met.
type ConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ConfigMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ConfigMultiError) AllErrors() []error { return m }

// ConfigValidationError is the validation error returned by Config.Validate if
// the designated constraints aren't met.
type ConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ConfigValidationError) ErrorName() string { return "ConfigValidationError" }

// Error satisfies the builtin error interface
func (e ConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ConfigValidationError{}

// Validate checks the field values on Auth with the rules defined in the proto
// definition for this message. If any rules are violated, the first error
// encountered is returned, or nil if there are no violations.
func (m *Auth) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Auth with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in AuthMultiError, or nil if none found.
func (m *Auth) ValidateAll() error {
	return m.validate(true)
}

func (m *Auth) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetAccessKey()) < 1 {
		err := AuthValidationError{
			field:  "AccessKey",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if m.GetAccessExp() <= 0 {
		err := AuthValidationError{
			field:  "AccessExp",
			reason: "value must be greater than 0",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if utf8.RuneCountInString(m.GetRefreshKey()) < 1 {
		err := AuthValidationError{
			field:  "RefreshKey",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if m.GetRefreshExp() <= 0 {
		err := AuthValidationError{
			field:  "RefreshExp",
			reason: "value must be greater than 0",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return AuthMultiError(errors)
	}

	return nil
}

// AuthMultiError is an error wrapping multiple validation errors returned by
// Auth.ValidateAll() if the designated constraints aren't met.
type AuthMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AuthMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AuthMultiError) AllErrors() []error { return m }

// AuthValidationError is the validation error returned by Auth.Validate if the
// designated constraints aren't met.
type AuthValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AuthValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AuthValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AuthValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AuthValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AuthValidationError) ErrorName() string { return "AuthValidationError" }

// Error satisfies the builtin error interface
func (e AuthValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAuth.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AuthValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AuthValidationError{}

// Validate checks the field values on Google with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *Google) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Google with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in GoogleMultiError, or nil if none found.
func (m *Google) ValidateAll() error {
	return m.validate(true)
}

func (m *Google) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetClientID()) < 1 {
		err := GoogleValidationError{
			field:  "ClientID",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return GoogleMultiError(errors)
	}

	return nil
}

// GoogleMultiError is an error wrapping multiple validation errors returned by
// Google.ValidateAll() if the designated constraints aren't met.
type GoogleMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m GoogleMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m GoogleMultiError) AllErrors() []error { return m }

// GoogleValidationError is the validation error returned by Google.Validate if
// the designated constraints aren't met.
type GoogleValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e GoogleValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e GoogleValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e GoogleValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e GoogleValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e GoogleValidationError) ErrorName() string { return "GoogleValidationError" }

// Error satisfies the builtin error interface
func (e GoogleValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sGoogle.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = GoogleValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = GoogleValidationError{}

// Validate checks the field values on FrontEnd with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *FrontEnd) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on FrontEnd with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in FrontEndMultiError, or nil
// if none found.
func (m *FrontEnd) ValidateAll() error {
	return m.validate(true)
}

func (m *FrontEnd) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetUrl()) < 1 {
		err := FrontEndValidationError{
			field:  "Url",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if utf8.RuneCountInString(m.GetResetPasswordEndpoint()) < 0 {
		err := FrontEndValidationError{
			field:  "ResetPasswordEndpoint",
			reason: "value length must be at least 0 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return FrontEndMultiError(errors)
	}

	return nil
}

// FrontEndMultiError is an error wrapping multiple validation errors returned
// by FrontEnd.ValidateAll() if the designated constraints aren't met.
type FrontEndMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m FrontEndMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m FrontEndMultiError) AllErrors() []error { return m }

// FrontEndValidationError is the validation error returned by
// FrontEnd.Validate if the designated constraints aren't met.
type FrontEndValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e FrontEndValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e FrontEndValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e FrontEndValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e FrontEndValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e FrontEndValidationError) ErrorName() string { return "FrontEndValidationError" }

// Error satisfies the builtin error interface
func (e FrontEndValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sFrontEnd.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = FrontEndValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = FrontEndValidationError{}

// Validate checks the field values on Mailer with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *Mailer) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Mailer with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in MailerMultiError, or nil if none found.
func (m *Mailer) ValidateAll() error {
	return m.validate(true)
}

func (m *Mailer) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetDomain()) < 1 {
		err := MailerValidationError{
			field:  "Domain",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if utf8.RuneCountInString(m.GetEndpoint()) < 1 {
		err := MailerValidationError{
			field:  "Endpoint",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return MailerMultiError(errors)
	}

	return nil
}

// MailerMultiError is an error wrapping multiple validation errors returned by
// Mailer.ValidateAll() if the designated constraints aren't met.
type MailerMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m MailerMultiError) Error() string {
	msgs := make([]string, 0, len(m))
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m MailerMultiError) AllErrors() []error { return m }

// MailerValidationError is the validation error returned by Mailer.Validate if
// the designated constraints aren't met.
type MailerValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e MailerValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e MailerValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e MailerValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e MailerValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e MailerValidationError) ErrorName() string { return "MailerValidationError" }

// Error satisfies the builtin error interface
func (e MailerValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMailer.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = MailerValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = MailerValidationError{}
