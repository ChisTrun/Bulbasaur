package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

type TransactionHistory struct {
	ent.Schema
}

func (TransactionHistory) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Base{},
	}
}

func (TransactionHistory) Fields() []ent.Field {
	return []ent.Field{
		field.Uint64("user_id"),
		field.Float("amount"),
		field.String("note"),
	}
}
