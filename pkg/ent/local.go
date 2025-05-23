// Code generated by ent, DO NOT EDIT.

package ent

import (
	"bulbasaur/pkg/ent/local"
	"bulbasaur/pkg/ent/user"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
)

// Local is the model entity for the Local schema.
type Local struct {
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
	// Username holds the value of the "username" field.
	Username string `json:"username,omitempty"`
	// Password holds the value of the "password" field.
	Password string `json:"password,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the LocalQuery when eager-loading is set.
	Edges        LocalEdges `json:"edges"`
	selectValues sql.SelectValues
}

// LocalEdges holds the relations/edges for other nodes in the graph.
type LocalEdges struct {
	// User holds the value of the user edge.
	User *User `json:"user,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// UserOrErr returns the User value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e LocalEdges) UserOrErr() (*User, error) {
	if e.User != nil {
		return e.User, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: user.Label}
	}
	return nil, &NotLoadedError{edge: "user"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Local) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case local.FieldID, local.FieldUserID:
			values[i] = new(sql.NullInt64)
		case local.FieldTenantID, local.FieldUsername, local.FieldPassword:
			values[i] = new(sql.NullString)
		case local.FieldCreatedAt, local.FieldUpdatedAt:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Local fields.
func (l *Local) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case local.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			l.ID = uint64(value.Int64)
		case local.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				l.CreatedAt = value.Time
			}
		case local.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				l.UpdatedAt = value.Time
			}
		case local.FieldTenantID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field tenant_id", values[i])
			} else if value.Valid {
				l.TenantID = value.String
			}
		case local.FieldUserID:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field user_id", values[i])
			} else if value.Valid {
				l.UserID = uint64(value.Int64)
			}
		case local.FieldUsername:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field username", values[i])
			} else if value.Valid {
				l.Username = value.String
			}
		case local.FieldPassword:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field password", values[i])
			} else if value.Valid {
				l.Password = value.String
			}
		default:
			l.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Local.
// This includes values selected through modifiers, order, etc.
func (l *Local) Value(name string) (ent.Value, error) {
	return l.selectValues.Get(name)
}

// QueryUser queries the "user" edge of the Local entity.
func (l *Local) QueryUser() *UserQuery {
	return NewLocalClient(l.config).QueryUser(l)
}

// Update returns a builder for updating this Local.
// Note that you need to call Local.Unwrap() before calling this method if this Local
// was returned from a transaction, and the transaction was committed or rolled back.
func (l *Local) Update() *LocalUpdateOne {
	return NewLocalClient(l.config).UpdateOne(l)
}

// Unwrap unwraps the Local entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (l *Local) Unwrap() *Local {
	_tx, ok := l.config.driver.(*txDriver)
	if !ok {
		panic("ent: Local is not a transactional entity")
	}
	l.config.driver = _tx.drv
	return l
}

// String implements the fmt.Stringer.
func (l *Local) String() string {
	var builder strings.Builder
	builder.WriteString("Local(")
	builder.WriteString(fmt.Sprintf("id=%v, ", l.ID))
	builder.WriteString("created_at=")
	builder.WriteString(l.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(l.UpdatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("tenant_id=")
	builder.WriteString(l.TenantID)
	builder.WriteString(", ")
	builder.WriteString("user_id=")
	builder.WriteString(fmt.Sprintf("%v", l.UserID))
	builder.WriteString(", ")
	builder.WriteString("username=")
	builder.WriteString(l.Username)
	builder.WriteString(", ")
	builder.WriteString("password=")
	builder.WriteString(l.Password)
	builder.WriteByte(')')
	return builder.String()
}

// Locals is a parsable slice of Local.
type Locals []*Local
