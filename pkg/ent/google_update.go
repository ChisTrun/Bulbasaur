// Code generated by ent, DO NOT EDIT.

package ent

import (
	"bulbasaur/pkg/ent/google"
	"bulbasaur/pkg/ent/predicate"
	"bulbasaur/pkg/ent/user"
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
)

// GoogleUpdate is the builder for updating Google entities.
type GoogleUpdate struct {
	config
	hooks     []Hook
	mutation  *GoogleMutation
	modifiers []func(*sql.UpdateBuilder)
}

// Where appends a list predicates to the GoogleUpdate builder.
func (gu *GoogleUpdate) Where(ps ...predicate.Google) *GoogleUpdate {
	gu.mutation.Where(ps...)
	return gu
}

// SetUpdatedAt sets the "updated_at" field.
func (gu *GoogleUpdate) SetUpdatedAt(t time.Time) *GoogleUpdate {
	gu.mutation.SetUpdatedAt(t)
	return gu
}

// SetTenantID sets the "tenant_id" field.
func (gu *GoogleUpdate) SetTenantID(s string) *GoogleUpdate {
	gu.mutation.SetTenantID(s)
	return gu
}

// SetNillableTenantID sets the "tenant_id" field if the given value is not nil.
func (gu *GoogleUpdate) SetNillableTenantID(s *string) *GoogleUpdate {
	if s != nil {
		gu.SetTenantID(*s)
	}
	return gu
}

// SetUserID sets the "user_id" field.
func (gu *GoogleUpdate) SetUserID(u uint64) *GoogleUpdate {
	gu.mutation.SetUserID(u)
	return gu
}

// SetNillableUserID sets the "user_id" field if the given value is not nil.
func (gu *GoogleUpdate) SetNillableUserID(u *uint64) *GoogleUpdate {
	if u != nil {
		gu.SetUserID(*u)
	}
	return gu
}

// SetEmail sets the "email" field.
func (gu *GoogleUpdate) SetEmail(s string) *GoogleUpdate {
	gu.mutation.SetEmail(s)
	return gu
}

// SetNillableEmail sets the "email" field if the given value is not nil.
func (gu *GoogleUpdate) SetNillableEmail(s *string) *GoogleUpdate {
	if s != nil {
		gu.SetEmail(*s)
	}
	return gu
}

// SetUser sets the "user" edge to the User entity.
func (gu *GoogleUpdate) SetUser(u *User) *GoogleUpdate {
	return gu.SetUserID(u.ID)
}

// Mutation returns the GoogleMutation object of the builder.
func (gu *GoogleUpdate) Mutation() *GoogleMutation {
	return gu.mutation
}

// ClearUser clears the "user" edge to the User entity.
func (gu *GoogleUpdate) ClearUser() *GoogleUpdate {
	gu.mutation.ClearUser()
	return gu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (gu *GoogleUpdate) Save(ctx context.Context) (int, error) {
	gu.defaults()
	return withHooks(ctx, gu.sqlSave, gu.mutation, gu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (gu *GoogleUpdate) SaveX(ctx context.Context) int {
	affected, err := gu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (gu *GoogleUpdate) Exec(ctx context.Context) error {
	_, err := gu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (gu *GoogleUpdate) ExecX(ctx context.Context) {
	if err := gu.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (gu *GoogleUpdate) defaults() {
	if _, ok := gu.mutation.UpdatedAt(); !ok {
		v := google.UpdateDefaultUpdatedAt()
		gu.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (gu *GoogleUpdate) check() error {
	if v, ok := gu.mutation.Email(); ok {
		if err := google.EmailValidator(v); err != nil {
			return &ValidationError{Name: "email", err: fmt.Errorf(`ent: validator failed for field "Google.email": %w`, err)}
		}
	}
	if gu.mutation.UserCleared() && len(gu.mutation.UserIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "Google.user"`)
	}
	return nil
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (gu *GoogleUpdate) Modify(modifiers ...func(u *sql.UpdateBuilder)) *GoogleUpdate {
	gu.modifiers = append(gu.modifiers, modifiers...)
	return gu
}

func (gu *GoogleUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := gu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(google.Table, google.Columns, sqlgraph.NewFieldSpec(google.FieldID, field.TypeUint64))
	if ps := gu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := gu.mutation.UpdatedAt(); ok {
		_spec.SetField(google.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := gu.mutation.TenantID(); ok {
		_spec.SetField(google.FieldTenantID, field.TypeString, value)
	}
	if value, ok := gu.mutation.Email(); ok {
		_spec.SetField(google.FieldEmail, field.TypeString, value)
	}
	if gu.mutation.UserCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   google.UserTable,
			Columns: []string{google.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUint64),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := gu.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   google.UserTable,
			Columns: []string{google.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUint64),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_spec.AddModifiers(gu.modifiers...)
	if n, err = sqlgraph.UpdateNodes(ctx, gu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{google.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	gu.mutation.done = true
	return n, nil
}

// GoogleUpdateOne is the builder for updating a single Google entity.
type GoogleUpdateOne struct {
	config
	fields    []string
	hooks     []Hook
	mutation  *GoogleMutation
	modifiers []func(*sql.UpdateBuilder)
}

// SetUpdatedAt sets the "updated_at" field.
func (guo *GoogleUpdateOne) SetUpdatedAt(t time.Time) *GoogleUpdateOne {
	guo.mutation.SetUpdatedAt(t)
	return guo
}

// SetTenantID sets the "tenant_id" field.
func (guo *GoogleUpdateOne) SetTenantID(s string) *GoogleUpdateOne {
	guo.mutation.SetTenantID(s)
	return guo
}

// SetNillableTenantID sets the "tenant_id" field if the given value is not nil.
func (guo *GoogleUpdateOne) SetNillableTenantID(s *string) *GoogleUpdateOne {
	if s != nil {
		guo.SetTenantID(*s)
	}
	return guo
}

// SetUserID sets the "user_id" field.
func (guo *GoogleUpdateOne) SetUserID(u uint64) *GoogleUpdateOne {
	guo.mutation.SetUserID(u)
	return guo
}

// SetNillableUserID sets the "user_id" field if the given value is not nil.
func (guo *GoogleUpdateOne) SetNillableUserID(u *uint64) *GoogleUpdateOne {
	if u != nil {
		guo.SetUserID(*u)
	}
	return guo
}

// SetEmail sets the "email" field.
func (guo *GoogleUpdateOne) SetEmail(s string) *GoogleUpdateOne {
	guo.mutation.SetEmail(s)
	return guo
}

// SetNillableEmail sets the "email" field if the given value is not nil.
func (guo *GoogleUpdateOne) SetNillableEmail(s *string) *GoogleUpdateOne {
	if s != nil {
		guo.SetEmail(*s)
	}
	return guo
}

// SetUser sets the "user" edge to the User entity.
func (guo *GoogleUpdateOne) SetUser(u *User) *GoogleUpdateOne {
	return guo.SetUserID(u.ID)
}

// Mutation returns the GoogleMutation object of the builder.
func (guo *GoogleUpdateOne) Mutation() *GoogleMutation {
	return guo.mutation
}

// ClearUser clears the "user" edge to the User entity.
func (guo *GoogleUpdateOne) ClearUser() *GoogleUpdateOne {
	guo.mutation.ClearUser()
	return guo
}

// Where appends a list predicates to the GoogleUpdate builder.
func (guo *GoogleUpdateOne) Where(ps ...predicate.Google) *GoogleUpdateOne {
	guo.mutation.Where(ps...)
	return guo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (guo *GoogleUpdateOne) Select(field string, fields ...string) *GoogleUpdateOne {
	guo.fields = append([]string{field}, fields...)
	return guo
}

// Save executes the query and returns the updated Google entity.
func (guo *GoogleUpdateOne) Save(ctx context.Context) (*Google, error) {
	guo.defaults()
	return withHooks(ctx, guo.sqlSave, guo.mutation, guo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (guo *GoogleUpdateOne) SaveX(ctx context.Context) *Google {
	node, err := guo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (guo *GoogleUpdateOne) Exec(ctx context.Context) error {
	_, err := guo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (guo *GoogleUpdateOne) ExecX(ctx context.Context) {
	if err := guo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (guo *GoogleUpdateOne) defaults() {
	if _, ok := guo.mutation.UpdatedAt(); !ok {
		v := google.UpdateDefaultUpdatedAt()
		guo.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (guo *GoogleUpdateOne) check() error {
	if v, ok := guo.mutation.Email(); ok {
		if err := google.EmailValidator(v); err != nil {
			return &ValidationError{Name: "email", err: fmt.Errorf(`ent: validator failed for field "Google.email": %w`, err)}
		}
	}
	if guo.mutation.UserCleared() && len(guo.mutation.UserIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "Google.user"`)
	}
	return nil
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (guo *GoogleUpdateOne) Modify(modifiers ...func(u *sql.UpdateBuilder)) *GoogleUpdateOne {
	guo.modifiers = append(guo.modifiers, modifiers...)
	return guo
}

func (guo *GoogleUpdateOne) sqlSave(ctx context.Context) (_node *Google, err error) {
	if err := guo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(google.Table, google.Columns, sqlgraph.NewFieldSpec(google.FieldID, field.TypeUint64))
	id, ok := guo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Google.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := guo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, google.FieldID)
		for _, f := range fields {
			if !google.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != google.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := guo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := guo.mutation.UpdatedAt(); ok {
		_spec.SetField(google.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := guo.mutation.TenantID(); ok {
		_spec.SetField(google.FieldTenantID, field.TypeString, value)
	}
	if value, ok := guo.mutation.Email(); ok {
		_spec.SetField(google.FieldEmail, field.TypeString, value)
	}
	if guo.mutation.UserCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   google.UserTable,
			Columns: []string{google.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUint64),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := guo.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   google.UserTable,
			Columns: []string{google.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUint64),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_spec.AddModifiers(guo.modifiers...)
	_node = &Google{config: guo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, guo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{google.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	guo.mutation.done = true
	return _node, nil
}
