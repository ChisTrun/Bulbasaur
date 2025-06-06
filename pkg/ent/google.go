// Code generated by ent, DO NOT EDIT.

package ent

import (
	"bulbasaur/pkg/ent/google"
	"bulbasaur/pkg/ent/user"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
)

// Google is the model entity for the Google schema.
type Google struct {
	config `json:"-"`
	// ID of the ent.
	ID uint64 `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// TenantID holds the value of the "tenant_id" field.
	TenantID string `json:"tenant_id,omitempty"`
	// UserID holds the value of the "user_id" field.
	UserID uint64 `json:"user_id,omitempty"`
	// Email holds the value of the "email" field.
	Email string `json:"email,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the GoogleQuery when eager-loading is set.
	Edges        GoogleEdges `json:"edges"`
	selectValues sql.SelectValues
}

// GoogleEdges holds the relations/edges for other nodes in the graph.
type GoogleEdges struct {
	// User holds the value of the user edge.
	User *User `json:"user,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// UserOrErr returns the User value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e GoogleEdges) UserOrErr() (*User, error) {
	if e.User != nil {
		return e.User, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: user.Label}
	}
	return nil, &NotLoadedError{edge: "user"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Google) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case google.FieldID, google.FieldUserID:
			values[i] = new(sql.NullInt64)
		case google.FieldTenantID, google.FieldEmail:
			values[i] = new(sql.NullString)
		case google.FieldCreatedAt, google.FieldUpdatedAt:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Google fields.
func (_go *Google) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case google.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			_go.ID = uint64(value.Int64)
		case google.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				_go.CreatedAt = value.Time
			}
		case google.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				_go.UpdatedAt = value.Time
			}
		case google.FieldTenantID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field tenant_id", values[i])
			} else if value.Valid {
				_go.TenantID = value.String
			}
		case google.FieldUserID:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field user_id", values[i])
			} else if value.Valid {
				_go.UserID = uint64(value.Int64)
			}
		case google.FieldEmail:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field email", values[i])
			} else if value.Valid {
				_go.Email = value.String
			}
		default:
			_go.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Google.
// This includes values selected through modifiers, order, etc.
func (_go *Google) Value(name string) (ent.Value, error) {
	return _go.selectValues.Get(name)
}

// QueryUser queries the "user" edge of the Google entity.
func (_go *Google) QueryUser() *UserQuery {
	return NewGoogleClient(_go.config).QueryUser(_go)
}

// Update returns a builder for updating this Google.
// Note that you need to call Google.Unwrap() before calling this method if this Google
// was returned from a transaction, and the transaction was committed or rolled back.
func (_go *Google) Update() *GoogleUpdateOne {
	return NewGoogleClient(_go.config).UpdateOne(_go)
}

// Unwrap unwraps the Google entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (_go *Google) Unwrap() *Google {
	_tx, ok := _go.config.driver.(*txDriver)
	if !ok {
		panic("ent: Google is not a transactional entity")
	}
	_go.config.driver = _tx.drv
	return _go
}

// String implements the fmt.Stringer.
func (_go *Google) String() string {
	var builder strings.Builder
	builder.WriteString("Google(")
	builder.WriteString(fmt.Sprintf("id=%v, ", _go.ID))
	builder.WriteString("created_at=")
	builder.WriteString(_go.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(_go.UpdatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("tenant_id=")
	builder.WriteString(_go.TenantID)
	builder.WriteString(", ")
	builder.WriteString("user_id=")
	builder.WriteString(fmt.Sprintf("%v", _go.UserID))
	builder.WriteString(", ")
	builder.WriteString("email=")
	builder.WriteString(_go.Email)
	builder.WriteByte(')')
	return builder.String()
}

// Googles is a parsable slice of Google.
type Googles []*Google
