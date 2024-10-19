package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Local struct {
	ent.Schema
}

func (Local) Fields() []ent.Field {
	return []ent.Field{
		field.String("tenant_id"),
		field.Uint64("user_id"),
		field.String("username").Optional(),
		field.String("password").Optional(),
	}
}

func (Local) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Base{},
	}
}

func (Local) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("my_id").
			Field("user_id").
			Unique().
			Required(),
	}
}

func (Local) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "username").Unique(),
	}
}
