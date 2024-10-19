package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type Action struct {
	ent.Schema
}

func (Action) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Base{},
	}
}

func (Action) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").Unique().NotEmpty(),
		field.Text("description").Optional(),
	}
}

func (Action) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("permission", Permission.Type).Annotations(
			entsql.Annotation{
				OnDelete: entsql.Cascade,
			},
		),
	}
}
