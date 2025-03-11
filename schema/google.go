package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Google struct {
	ent.Schema
}

func (Google) Fields() []ent.Field {
	return []ent.Field{
		field.String("tenant_id"),
		field.Uint64("user_id"),
		field.String("email").NotEmpty(),
	}
}

func (Google) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Base{},
	}
}

func (Google) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("google").
			Field("user_id").
			Unique().
			Required(),
	}
}

func (Google) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "email").Unique(),
	}
}
