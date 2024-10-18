// Code generated by ent, DO NOT EDIT.

package ent

import (
	"bulbasaur/package/ent/google"
	"bulbasaur/package/ent/myid"
	"bulbasaur/package/ent/user"
	"bulbasaur/schema"
	"time"
)

// The init function reads all schema descriptors with runtime code
// (default values, validators, hooks and policies) and stitches it
// to their package variables.
func init() {
	googleMixin := schema.Google{}.Mixin()
	googleMixinFields0 := googleMixin[0].Fields()
	_ = googleMixinFields0
	googleFields := schema.Google{}.Fields()
	_ = googleFields
	// googleDescCreatedAt is the schema descriptor for created_at field.
	googleDescCreatedAt := googleMixinFields0[1].Descriptor()
	// google.DefaultCreatedAt holds the default value on creation for the created_at field.
	google.DefaultCreatedAt = googleDescCreatedAt.Default.(func() time.Time)
	// googleDescUpdatedAt is the schema descriptor for updated_at field.
	googleDescUpdatedAt := googleMixinFields0[2].Descriptor()
	// google.DefaultUpdatedAt holds the default value on creation for the updated_at field.
	google.DefaultUpdatedAt = googleDescUpdatedAt.Default.(func() time.Time)
	// google.UpdateDefaultUpdatedAt holds the default value on update for the updated_at field.
	google.UpdateDefaultUpdatedAt = googleDescUpdatedAt.UpdateDefault.(func() time.Time)
	// googleDescEmail is the schema descriptor for email field.
	googleDescEmail := googleFields[2].Descriptor()
	// google.EmailValidator is a validator for the "email" field. It is called by the builders before save.
	google.EmailValidator = googleDescEmail.Validators[0].(func(string) error)
	myidMixin := schema.MyID{}.Mixin()
	myidMixinFields0 := myidMixin[0].Fields()
	_ = myidMixinFields0
	myidFields := schema.MyID{}.Fields()
	_ = myidFields
	// myidDescCreatedAt is the schema descriptor for created_at field.
	myidDescCreatedAt := myidMixinFields0[1].Descriptor()
	// myid.DefaultCreatedAt holds the default value on creation for the created_at field.
	myid.DefaultCreatedAt = myidDescCreatedAt.Default.(func() time.Time)
	// myidDescUpdatedAt is the schema descriptor for updated_at field.
	myidDescUpdatedAt := myidMixinFields0[2].Descriptor()
	// myid.DefaultUpdatedAt holds the default value on creation for the updated_at field.
	myid.DefaultUpdatedAt = myidDescUpdatedAt.Default.(func() time.Time)
	// myid.UpdateDefaultUpdatedAt holds the default value on update for the updated_at field.
	myid.UpdateDefaultUpdatedAt = myidDescUpdatedAt.UpdateDefault.(func() time.Time)
	userMixin := schema.User{}.Mixin()
	userMixinFields0 := userMixin[0].Fields()
	_ = userMixinFields0
	userFields := schema.User{}.Fields()
	_ = userFields
	// userDescCreatedAt is the schema descriptor for created_at field.
	userDescCreatedAt := userMixinFields0[1].Descriptor()
	// user.DefaultCreatedAt holds the default value on creation for the created_at field.
	user.DefaultCreatedAt = userDescCreatedAt.Default.(func() time.Time)
	// userDescUpdatedAt is the schema descriptor for updated_at field.
	userDescUpdatedAt := userMixinFields0[2].Descriptor()
	// user.DefaultUpdatedAt holds the default value on creation for the updated_at field.
	user.DefaultUpdatedAt = userDescUpdatedAt.Default.(func() time.Time)
	// user.UpdateDefaultUpdatedAt holds the default value on update for the updated_at field.
	user.UpdateDefaultUpdatedAt = userDescUpdatedAt.UpdateDefault.(func() time.Time)
}
