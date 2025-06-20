// Code generated by ent, DO NOT EDIT.

package ent

import (
	"bulbasaur/pkg/ent/transactionhistory"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
)

// TransactionHistory is the model entity for the TransactionHistory schema.
type TransactionHistory struct {
	config `json:"-"`
	// ID of the ent.
	ID uint64 `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// UserID holds the value of the "user_id" field.
	UserID uint64 `json:"user_id,omitempty"`
	// Amount holds the value of the "amount" field.
	Amount float64 `json:"amount,omitempty"`
	// Note holds the value of the "note" field.
	Note         string `json:"note,omitempty"`
	selectValues sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*TransactionHistory) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case transactionhistory.FieldAmount:
			values[i] = new(sql.NullFloat64)
		case transactionhistory.FieldID, transactionhistory.FieldUserID:
			values[i] = new(sql.NullInt64)
		case transactionhistory.FieldNote:
			values[i] = new(sql.NullString)
		case transactionhistory.FieldCreatedAt, transactionhistory.FieldUpdatedAt:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the TransactionHistory fields.
func (th *TransactionHistory) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case transactionhistory.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			th.ID = uint64(value.Int64)
		case transactionhistory.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				th.CreatedAt = value.Time
			}
		case transactionhistory.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				th.UpdatedAt = value.Time
			}
		case transactionhistory.FieldUserID:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field user_id", values[i])
			} else if value.Valid {
				th.UserID = uint64(value.Int64)
			}
		case transactionhistory.FieldAmount:
			if value, ok := values[i].(*sql.NullFloat64); !ok {
				return fmt.Errorf("unexpected type %T for field amount", values[i])
			} else if value.Valid {
				th.Amount = value.Float64
			}
		case transactionhistory.FieldNote:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field note", values[i])
			} else if value.Valid {
				th.Note = value.String
			}
		default:
			th.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the TransactionHistory.
// This includes values selected through modifiers, order, etc.
func (th *TransactionHistory) Value(name string) (ent.Value, error) {
	return th.selectValues.Get(name)
}

// Update returns a builder for updating this TransactionHistory.
// Note that you need to call TransactionHistory.Unwrap() before calling this method if this TransactionHistory
// was returned from a transaction, and the transaction was committed or rolled back.
func (th *TransactionHistory) Update() *TransactionHistoryUpdateOne {
	return NewTransactionHistoryClient(th.config).UpdateOne(th)
}

// Unwrap unwraps the TransactionHistory entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (th *TransactionHistory) Unwrap() *TransactionHistory {
	_tx, ok := th.config.driver.(*txDriver)
	if !ok {
		panic("ent: TransactionHistory is not a transactional entity")
	}
	th.config.driver = _tx.drv
	return th
}

// String implements the fmt.Stringer.
func (th *TransactionHistory) String() string {
	var builder strings.Builder
	builder.WriteString("TransactionHistory(")
	builder.WriteString(fmt.Sprintf("id=%v, ", th.ID))
	builder.WriteString("created_at=")
	builder.WriteString(th.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(th.UpdatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("user_id=")
	builder.WriteString(fmt.Sprintf("%v", th.UserID))
	builder.WriteString(", ")
	builder.WriteString("amount=")
	builder.WriteString(fmt.Sprintf("%v", th.Amount))
	builder.WriteString(", ")
	builder.WriteString("note=")
	builder.WriteString(th.Note)
	builder.WriteByte(')')
	return builder.String()
}

// TransactionHistories is a parsable slice of TransactionHistory.
type TransactionHistories []*TransactionHistory
