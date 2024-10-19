package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type Permission struct {
	ent.Schema
}

func (Permission) Fields() []ent.Field {
	return []ent.Field{
		field.Uint64("action_id"),
		field.Uint64("role_id"),
	}
}

func (Permission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("action", Action.Type).Field("action_id").Required().Unique().Ref("permission"),
		edge.From("role", Role.Type).Field("role_id").Required().Unique().Ref("permission"),
	}
}

func (Permission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("role_id", "action_id").Unique(),
	}
}
