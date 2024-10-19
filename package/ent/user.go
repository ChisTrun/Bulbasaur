// Code generated by ent, DO NOT EDIT.

package ent

import (
	"bulbasaur/package/ent/google"
	"bulbasaur/package/ent/local"
	"bulbasaur/package/ent/role"
	"bulbasaur/package/ent/user"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
)

// User is the model entity for the User schema.
type User struct {
	config `json:"-"`
	// ID of the ent.
	ID uint64 `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// TenantID holds the value of the "tenant_id" field.
	TenantID string `json:"tenant_id,omitempty"`
	// Email holds the value of the "email" field.
	Email string `json:"email,omitempty"`
	// Metadata holds the value of the "metadata" field.
	Metadata *string `json:"metadata,omitempty"`
	// LastSignedIn holds the value of the "last_signed_in" field.
	LastSignedIn *time.Time `json:"last_signed_in,omitempty"`
	// RoleID holds the value of the "role_id" field.
	RoleID uint64 `json:"role_id,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the UserQuery when eager-loading is set.
	Edges        UserEdges `json:"edges"`
	selectValues sql.SelectValues
}

// UserEdges holds the relations/edges for other nodes in the graph.
type UserEdges struct {
	// MyID holds the value of the my_id edge.
	MyID *Local `json:"my_id,omitempty"`
	// Google holds the value of the google edge.
	Google *Google `json:"google,omitempty"`
	// Role holds the value of the role edge.
	Role *Role `json:"role,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [3]bool
}

// MyIDOrErr returns the MyID value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UserEdges) MyIDOrErr() (*Local, error) {
	if e.MyID != nil {
		return e.MyID, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: local.Label}
	}
	return nil, &NotLoadedError{edge: "my_id"}
}

// GoogleOrErr returns the Google value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UserEdges) GoogleOrErr() (*Google, error) {
	if e.Google != nil {
		return e.Google, nil
	} else if e.loadedTypes[1] {
		return nil, &NotFoundError{label: google.Label}
	}
	return nil, &NotLoadedError{edge: "google"}
}

// RoleOrErr returns the Role value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UserEdges) RoleOrErr() (*Role, error) {
	if e.Role != nil {
		return e.Role, nil
	} else if e.loadedTypes[2] {
		return nil, &NotFoundError{label: role.Label}
	}
	return nil, &NotLoadedError{edge: "role"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*User) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case user.FieldID, user.FieldRoleID:
			values[i] = new(sql.NullInt64)
		case user.FieldTenantID, user.FieldEmail, user.FieldMetadata:
			values[i] = new(sql.NullString)
		case user.FieldCreatedAt, user.FieldUpdatedAt, user.FieldLastSignedIn:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the User fields.
func (u *User) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case user.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			u.ID = uint64(value.Int64)
		case user.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				u.CreatedAt = value.Time
			}
		case user.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				u.UpdatedAt = value.Time
			}
		case user.FieldTenantID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field tenant_id", values[i])
			} else if value.Valid {
				u.TenantID = value.String
			}
		case user.FieldEmail:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field email", values[i])
			} else if value.Valid {
				u.Email = value.String
			}
		case user.FieldMetadata:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field metadata", values[i])
			} else if value.Valid {
				u.Metadata = new(string)
				*u.Metadata = value.String
			}
		case user.FieldLastSignedIn:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field last_signed_in", values[i])
			} else if value.Valid {
				u.LastSignedIn = new(time.Time)
				*u.LastSignedIn = value.Time
			}
		case user.FieldRoleID:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field role_id", values[i])
			} else if value.Valid {
				u.RoleID = uint64(value.Int64)
			}
		default:
			u.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the User.
// This includes values selected through modifiers, order, etc.
func (u *User) Value(name string) (ent.Value, error) {
	return u.selectValues.Get(name)
}

// QueryMyID queries the "my_id" edge of the User entity.
func (u *User) QueryMyID() *LocalQuery {
	return NewUserClient(u.config).QueryMyID(u)
}

// QueryGoogle queries the "google" edge of the User entity.
func (u *User) QueryGoogle() *GoogleQuery {
	return NewUserClient(u.config).QueryGoogle(u)
}

// QueryRole queries the "role" edge of the User entity.
func (u *User) QueryRole() *RoleQuery {
	return NewUserClient(u.config).QueryRole(u)
}

// Update returns a builder for updating this User.
// Note that you need to call User.Unwrap() before calling this method if this User
// was returned from a transaction, and the transaction was committed or rolled back.
func (u *User) Update() *UserUpdateOne {
	return NewUserClient(u.config).UpdateOne(u)
}

// Unwrap unwraps the User entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (u *User) Unwrap() *User {
	_tx, ok := u.config.driver.(*txDriver)
	if !ok {
		panic("ent: User is not a transactional entity")
	}
	u.config.driver = _tx.drv
	return u
}

// String implements the fmt.Stringer.
func (u *User) String() string {
	var builder strings.Builder
	builder.WriteString("User(")
	builder.WriteString(fmt.Sprintf("id=%v, ", u.ID))
	builder.WriteString("created_at=")
	builder.WriteString(u.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(u.UpdatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("tenant_id=")
	builder.WriteString(u.TenantID)
	builder.WriteString(", ")
	builder.WriteString("email=")
	builder.WriteString(u.Email)
	builder.WriteString(", ")
	if v := u.Metadata; v != nil {
		builder.WriteString("metadata=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := u.LastSignedIn; v != nil {
		builder.WriteString("last_signed_in=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	builder.WriteString("role_id=")
	builder.WriteString(fmt.Sprintf("%v", u.RoleID))
	builder.WriteByte(')')
	return builder.String()
}

// Users is a parsable slice of User.
type Users []*User
