package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type User struct {
	ent.Schema
}

func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Base{},
	}
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("tenant_id"),
		field.String("email").Optional(),
		field.Text("metadata").
			Optional().
			Nillable(),
		field.Time("last_signed_in").
			Optional().
			Nillable(),
		field.Uint64("role_id"),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("my_id", MyID.Type).Annotations(entsql.Annotation{
			OnDelete: entsql.Cascade,
		}).
			Unique(),
		edge.To("google", Google.Type).Annotations(entsql.Annotation{
			OnDelete: entsql.Cascade,
		}).
			Unique(),
		edge.From("role", Role.Type).Required().Unique().Ref("user").Field("role_id"),
	}
}

func (User) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "id").Unique(),
	}
}
