// Code generated by ent, DO NOT EDIT.

package user

import (
	"bulbasaur/package/ent/predicate"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

// ID filters vertices based on their ID field.
func ID(id uint64) predicate.User {
	return predicate.User(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id uint64) predicate.User {
	return predicate.User(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id uint64) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...uint64) predicate.User {
	return predicate.User(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...uint64) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id uint64) predicate.User {
	return predicate.User(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id uint64) predicate.User {
	return predicate.User(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id uint64) predicate.User {
	return predicate.User(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id uint64) predicate.User {
	return predicate.User(sql.FieldLTE(FieldID, id))
}

// CreatedAt applies equality check predicate on the "created_at" field. It's identical to CreatedAtEQ.
func CreatedAt(v time.Time) predicate.User {
	return predicate.User(sql.FieldEQ(FieldCreatedAt, v))
}

// UpdatedAt applies equality check predicate on the "updated_at" field. It's identical to UpdatedAtEQ.
func UpdatedAt(v time.Time) predicate.User {
	return predicate.User(sql.FieldEQ(FieldUpdatedAt, v))
}

// TenantID applies equality check predicate on the "tenant_id" field. It's identical to TenantIDEQ.
func TenantID(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldTenantID, v))
}

// Metadata applies equality check predicate on the "metadata" field. It's identical to MetadataEQ.
func Metadata(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldMetadata, v))
}

// LastSignedIn applies equality check predicate on the "last_signed_in" field. It's identical to LastSignedInEQ.
func LastSignedIn(v time.Time) predicate.User {
	return predicate.User(sql.FieldEQ(FieldLastSignedIn, v))
}

// CreatedAtEQ applies the EQ predicate on the "created_at" field.
func CreatedAtEQ(v time.Time) predicate.User {
	return predicate.User(sql.FieldEQ(FieldCreatedAt, v))
}

// CreatedAtNEQ applies the NEQ predicate on the "created_at" field.
func CreatedAtNEQ(v time.Time) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldCreatedAt, v))
}

// CreatedAtIn applies the In predicate on the "created_at" field.
func CreatedAtIn(vs ...time.Time) predicate.User {
	return predicate.User(sql.FieldIn(FieldCreatedAt, vs...))
}

// CreatedAtNotIn applies the NotIn predicate on the "created_at" field.
func CreatedAtNotIn(vs ...time.Time) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldCreatedAt, vs...))
}

// CreatedAtGT applies the GT predicate on the "created_at" field.
func CreatedAtGT(v time.Time) predicate.User {
	return predicate.User(sql.FieldGT(FieldCreatedAt, v))
}

// CreatedAtGTE applies the GTE predicate on the "created_at" field.
func CreatedAtGTE(v time.Time) predicate.User {
	return predicate.User(sql.FieldGTE(FieldCreatedAt, v))
}

// CreatedAtLT applies the LT predicate on the "created_at" field.
func CreatedAtLT(v time.Time) predicate.User {
	return predicate.User(sql.FieldLT(FieldCreatedAt, v))
}

// CreatedAtLTE applies the LTE predicate on the "created_at" field.
func CreatedAtLTE(v time.Time) predicate.User {
	return predicate.User(sql.FieldLTE(FieldCreatedAt, v))
}

// UpdatedAtEQ applies the EQ predicate on the "updated_at" field.
func UpdatedAtEQ(v time.Time) predicate.User {
	return predicate.User(sql.FieldEQ(FieldUpdatedAt, v))
}

// UpdatedAtNEQ applies the NEQ predicate on the "updated_at" field.
func UpdatedAtNEQ(v time.Time) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldUpdatedAt, v))
}

// UpdatedAtIn applies the In predicate on the "updated_at" field.
func UpdatedAtIn(vs ...time.Time) predicate.User {
	return predicate.User(sql.FieldIn(FieldUpdatedAt, vs...))
}

// UpdatedAtNotIn applies the NotIn predicate on the "updated_at" field.
func UpdatedAtNotIn(vs ...time.Time) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldUpdatedAt, vs...))
}

// UpdatedAtGT applies the GT predicate on the "updated_at" field.
func UpdatedAtGT(v time.Time) predicate.User {
	return predicate.User(sql.FieldGT(FieldUpdatedAt, v))
}

// UpdatedAtGTE applies the GTE predicate on the "updated_at" field.
func UpdatedAtGTE(v time.Time) predicate.User {
	return predicate.User(sql.FieldGTE(FieldUpdatedAt, v))
}

// UpdatedAtLT applies the LT predicate on the "updated_at" field.
func UpdatedAtLT(v time.Time) predicate.User {
	return predicate.User(sql.FieldLT(FieldUpdatedAt, v))
}

// UpdatedAtLTE applies the LTE predicate on the "updated_at" field.
func UpdatedAtLTE(v time.Time) predicate.User {
	return predicate.User(sql.FieldLTE(FieldUpdatedAt, v))
}

// TenantIDEQ applies the EQ predicate on the "tenant_id" field.
func TenantIDEQ(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldTenantID, v))
}

// TenantIDNEQ applies the NEQ predicate on the "tenant_id" field.
func TenantIDNEQ(v string) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldTenantID, v))
}

// TenantIDIn applies the In predicate on the "tenant_id" field.
func TenantIDIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldIn(FieldTenantID, vs...))
}

// TenantIDNotIn applies the NotIn predicate on the "tenant_id" field.
func TenantIDNotIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldTenantID, vs...))
}

// TenantIDGT applies the GT predicate on the "tenant_id" field.
func TenantIDGT(v string) predicate.User {
	return predicate.User(sql.FieldGT(FieldTenantID, v))
}

// TenantIDGTE applies the GTE predicate on the "tenant_id" field.
func TenantIDGTE(v string) predicate.User {
	return predicate.User(sql.FieldGTE(FieldTenantID, v))
}

// TenantIDLT applies the LT predicate on the "tenant_id" field.
func TenantIDLT(v string) predicate.User {
	return predicate.User(sql.FieldLT(FieldTenantID, v))
}

// TenantIDLTE applies the LTE predicate on the "tenant_id" field.
func TenantIDLTE(v string) predicate.User {
	return predicate.User(sql.FieldLTE(FieldTenantID, v))
}

// TenantIDContains applies the Contains predicate on the "tenant_id" field.
func TenantIDContains(v string) predicate.User {
	return predicate.User(sql.FieldContains(FieldTenantID, v))
}

// TenantIDHasPrefix applies the HasPrefix predicate on the "tenant_id" field.
func TenantIDHasPrefix(v string) predicate.User {
	return predicate.User(sql.FieldHasPrefix(FieldTenantID, v))
}

// TenantIDHasSuffix applies the HasSuffix predicate on the "tenant_id" field.
func TenantIDHasSuffix(v string) predicate.User {
	return predicate.User(sql.FieldHasSuffix(FieldTenantID, v))
}

// TenantIDEqualFold applies the EqualFold predicate on the "tenant_id" field.
func TenantIDEqualFold(v string) predicate.User {
	return predicate.User(sql.FieldEqualFold(FieldTenantID, v))
}

// TenantIDContainsFold applies the ContainsFold predicate on the "tenant_id" field.
func TenantIDContainsFold(v string) predicate.User {
	return predicate.User(sql.FieldContainsFold(FieldTenantID, v))
}

// MetadataEQ applies the EQ predicate on the "metadata" field.
func MetadataEQ(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldMetadata, v))
}

// MetadataNEQ applies the NEQ predicate on the "metadata" field.
func MetadataNEQ(v string) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldMetadata, v))
}

// MetadataIn applies the In predicate on the "metadata" field.
func MetadataIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldIn(FieldMetadata, vs...))
}

// MetadataNotIn applies the NotIn predicate on the "metadata" field.
func MetadataNotIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldMetadata, vs...))
}

// MetadataGT applies the GT predicate on the "metadata" field.
func MetadataGT(v string) predicate.User {
	return predicate.User(sql.FieldGT(FieldMetadata, v))
}

// MetadataGTE applies the GTE predicate on the "metadata" field.
func MetadataGTE(v string) predicate.User {
	return predicate.User(sql.FieldGTE(FieldMetadata, v))
}

// MetadataLT applies the LT predicate on the "metadata" field.
func MetadataLT(v string) predicate.User {
	return predicate.User(sql.FieldLT(FieldMetadata, v))
}

// MetadataLTE applies the LTE predicate on the "metadata" field.
func MetadataLTE(v string) predicate.User {
	return predicate.User(sql.FieldLTE(FieldMetadata, v))
}

// MetadataContains applies the Contains predicate on the "metadata" field.
func MetadataContains(v string) predicate.User {
	return predicate.User(sql.FieldContains(FieldMetadata, v))
}

// MetadataHasPrefix applies the HasPrefix predicate on the "metadata" field.
func MetadataHasPrefix(v string) predicate.User {
	return predicate.User(sql.FieldHasPrefix(FieldMetadata, v))
}

// MetadataHasSuffix applies the HasSuffix predicate on the "metadata" field.
func MetadataHasSuffix(v string) predicate.User {
	return predicate.User(sql.FieldHasSuffix(FieldMetadata, v))
}

// MetadataIsNil applies the IsNil predicate on the "metadata" field.
func MetadataIsNil() predicate.User {
	return predicate.User(sql.FieldIsNull(FieldMetadata))
}

// MetadataNotNil applies the NotNil predicate on the "metadata" field.
func MetadataNotNil() predicate.User {
	return predicate.User(sql.FieldNotNull(FieldMetadata))
}

// MetadataEqualFold applies the EqualFold predicate on the "metadata" field.
func MetadataEqualFold(v string) predicate.User {
	return predicate.User(sql.FieldEqualFold(FieldMetadata, v))
}

// MetadataContainsFold applies the ContainsFold predicate on the "metadata" field.
func MetadataContainsFold(v string) predicate.User {
	return predicate.User(sql.FieldContainsFold(FieldMetadata, v))
}

// LastSignedInEQ applies the EQ predicate on the "last_signed_in" field.
func LastSignedInEQ(v time.Time) predicate.User {
	return predicate.User(sql.FieldEQ(FieldLastSignedIn, v))
}

// LastSignedInNEQ applies the NEQ predicate on the "last_signed_in" field.
func LastSignedInNEQ(v time.Time) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldLastSignedIn, v))
}

// LastSignedInIn applies the In predicate on the "last_signed_in" field.
func LastSignedInIn(vs ...time.Time) predicate.User {
	return predicate.User(sql.FieldIn(FieldLastSignedIn, vs...))
}

// LastSignedInNotIn applies the NotIn predicate on the "last_signed_in" field.
func LastSignedInNotIn(vs ...time.Time) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldLastSignedIn, vs...))
}

// LastSignedInGT applies the GT predicate on the "last_signed_in" field.
func LastSignedInGT(v time.Time) predicate.User {
	return predicate.User(sql.FieldGT(FieldLastSignedIn, v))
}

// LastSignedInGTE applies the GTE predicate on the "last_signed_in" field.
func LastSignedInGTE(v time.Time) predicate.User {
	return predicate.User(sql.FieldGTE(FieldLastSignedIn, v))
}

// LastSignedInLT applies the LT predicate on the "last_signed_in" field.
func LastSignedInLT(v time.Time) predicate.User {
	return predicate.User(sql.FieldLT(FieldLastSignedIn, v))
}

// LastSignedInLTE applies the LTE predicate on the "last_signed_in" field.
func LastSignedInLTE(v time.Time) predicate.User {
	return predicate.User(sql.FieldLTE(FieldLastSignedIn, v))
}

// LastSignedInIsNil applies the IsNil predicate on the "last_signed_in" field.
func LastSignedInIsNil() predicate.User {
	return predicate.User(sql.FieldIsNull(FieldLastSignedIn))
}

// LastSignedInNotNil applies the NotNil predicate on the "last_signed_in" field.
func LastSignedInNotNil() predicate.User {
	return predicate.User(sql.FieldNotNull(FieldLastSignedIn))
}

// HasMyID applies the HasEdge predicate on the "my_id" edge.
func HasMyID() predicate.User {
	return predicate.User(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, MyIDTable, MyIDColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasMyIDWith applies the HasEdge predicate on the "my_id" edge with a given conditions (other predicates).
func HasMyIDWith(preds ...predicate.MyID) predicate.User {
	return predicate.User(func(s *sql.Selector) {
		step := newMyIDStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasGoogle applies the HasEdge predicate on the "google" edge.
func HasGoogle() predicate.User {
	return predicate.User(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, GoogleTable, GoogleColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasGoogleWith applies the HasEdge predicate on the "google" edge with a given conditions (other predicates).
func HasGoogleWith(preds ...predicate.Google) predicate.User {
	return predicate.User(func(s *sql.Selector) {
		step := newGoogleStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.User) predicate.User {
	return predicate.User(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.User) predicate.User {
	return predicate.User(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.User) predicate.User {
	return predicate.User(sql.NotPredicates(p))
}
