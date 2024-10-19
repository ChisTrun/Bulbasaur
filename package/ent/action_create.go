// Code generated by ent, DO NOT EDIT.

package ent

import (
	"bulbasaur/package/ent/action"
	"bulbasaur/package/ent/permission"
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
)

// ActionCreate is the builder for creating a Action entity.
type ActionCreate struct {
	config
	mutation *ActionMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetCreatedAt sets the "created_at" field.
func (ac *ActionCreate) SetCreatedAt(t time.Time) *ActionCreate {
	ac.mutation.SetCreatedAt(t)
	return ac
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (ac *ActionCreate) SetNillableCreatedAt(t *time.Time) *ActionCreate {
	if t != nil {
		ac.SetCreatedAt(*t)
	}
	return ac
}

// SetUpdatedAt sets the "updated_at" field.
func (ac *ActionCreate) SetUpdatedAt(t time.Time) *ActionCreate {
	ac.mutation.SetUpdatedAt(t)
	return ac
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (ac *ActionCreate) SetNillableUpdatedAt(t *time.Time) *ActionCreate {
	if t != nil {
		ac.SetUpdatedAt(*t)
	}
	return ac
}

// SetName sets the "name" field.
func (ac *ActionCreate) SetName(s string) *ActionCreate {
	ac.mutation.SetName(s)
	return ac
}

// SetDescription sets the "description" field.
func (ac *ActionCreate) SetDescription(s string) *ActionCreate {
	ac.mutation.SetDescription(s)
	return ac
}

// SetNillableDescription sets the "description" field if the given value is not nil.
func (ac *ActionCreate) SetNillableDescription(s *string) *ActionCreate {
	if s != nil {
		ac.SetDescription(*s)
	}
	return ac
}

// SetID sets the "id" field.
func (ac *ActionCreate) SetID(u uint64) *ActionCreate {
	ac.mutation.SetID(u)
	return ac
}

// AddPermissionIDs adds the "permission" edge to the Permission entity by IDs.
func (ac *ActionCreate) AddPermissionIDs(ids ...int) *ActionCreate {
	ac.mutation.AddPermissionIDs(ids...)
	return ac
}

// AddPermission adds the "permission" edges to the Permission entity.
func (ac *ActionCreate) AddPermission(p ...*Permission) *ActionCreate {
	ids := make([]int, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return ac.AddPermissionIDs(ids...)
}

// Mutation returns the ActionMutation object of the builder.
func (ac *ActionCreate) Mutation() *ActionMutation {
	return ac.mutation
}

// Save creates the Action in the database.
func (ac *ActionCreate) Save(ctx context.Context) (*Action, error) {
	ac.defaults()
	return withHooks(ctx, ac.sqlSave, ac.mutation, ac.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (ac *ActionCreate) SaveX(ctx context.Context) *Action {
	v, err := ac.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ac *ActionCreate) Exec(ctx context.Context) error {
	_, err := ac.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ac *ActionCreate) ExecX(ctx context.Context) {
	if err := ac.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (ac *ActionCreate) defaults() {
	if _, ok := ac.mutation.CreatedAt(); !ok {
		v := action.DefaultCreatedAt()
		ac.mutation.SetCreatedAt(v)
	}
	if _, ok := ac.mutation.UpdatedAt(); !ok {
		v := action.DefaultUpdatedAt()
		ac.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ac *ActionCreate) check() error {
	if _, ok := ac.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "Action.created_at"`)}
	}
	if _, ok := ac.mutation.UpdatedAt(); !ok {
		return &ValidationError{Name: "updated_at", err: errors.New(`ent: missing required field "Action.updated_at"`)}
	}
	if _, ok := ac.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New(`ent: missing required field "Action.name"`)}
	}
	if v, ok := ac.mutation.Name(); ok {
		if err := action.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "Action.name": %w`, err)}
		}
	}
	return nil
}

func (ac *ActionCreate) sqlSave(ctx context.Context) (*Action, error) {
	if err := ac.check(); err != nil {
		return nil, err
	}
	_node, _spec := ac.createSpec()
	if err := sqlgraph.CreateNode(ctx, ac.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != _node.ID {
		id := _spec.ID.Value.(int64)
		_node.ID = uint64(id)
	}
	ac.mutation.id = &_node.ID
	ac.mutation.done = true
	return _node, nil
}

func (ac *ActionCreate) createSpec() (*Action, *sqlgraph.CreateSpec) {
	var (
		_node = &Action{config: ac.config}
		_spec = sqlgraph.NewCreateSpec(action.Table, sqlgraph.NewFieldSpec(action.FieldID, field.TypeUint64))
	)
	_spec.OnConflict = ac.conflict
	if id, ok := ac.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := ac.mutation.CreatedAt(); ok {
		_spec.SetField(action.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := ac.mutation.UpdatedAt(); ok {
		_spec.SetField(action.FieldUpdatedAt, field.TypeTime, value)
		_node.UpdatedAt = value
	}
	if value, ok := ac.mutation.Name(); ok {
		_spec.SetField(action.FieldName, field.TypeString, value)
		_node.Name = value
	}
	if value, ok := ac.mutation.Description(); ok {
		_spec.SetField(action.FieldDescription, field.TypeString, value)
		_node.Description = value
	}
	if nodes := ac.mutation.PermissionIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   action.PermissionTable,
			Columns: []string{action.PermissionColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(permission.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Action.Create().
//		SetCreatedAt(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.ActionUpsert) {
//			SetCreatedAt(v+v).
//		}).
//		Exec(ctx)
func (ac *ActionCreate) OnConflict(opts ...sql.ConflictOption) *ActionUpsertOne {
	ac.conflict = opts
	return &ActionUpsertOne{
		create: ac,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Action.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (ac *ActionCreate) OnConflictColumns(columns ...string) *ActionUpsertOne {
	ac.conflict = append(ac.conflict, sql.ConflictColumns(columns...))
	return &ActionUpsertOne{
		create: ac,
	}
}

type (
	// ActionUpsertOne is the builder for "upsert"-ing
	//  one Action node.
	ActionUpsertOne struct {
		create *ActionCreate
	}

	// ActionUpsert is the "OnConflict" setter.
	ActionUpsert struct {
		*sql.UpdateSet
	}
)

// SetUpdatedAt sets the "updated_at" field.
func (u *ActionUpsert) SetUpdatedAt(v time.Time) *ActionUpsert {
	u.Set(action.FieldUpdatedAt, v)
	return u
}

// UpdateUpdatedAt sets the "updated_at" field to the value that was provided on create.
func (u *ActionUpsert) UpdateUpdatedAt() *ActionUpsert {
	u.SetExcluded(action.FieldUpdatedAt)
	return u
}

// SetName sets the "name" field.
func (u *ActionUpsert) SetName(v string) *ActionUpsert {
	u.Set(action.FieldName, v)
	return u
}

// UpdateName sets the "name" field to the value that was provided on create.
func (u *ActionUpsert) UpdateName() *ActionUpsert {
	u.SetExcluded(action.FieldName)
	return u
}

// SetDescription sets the "description" field.
func (u *ActionUpsert) SetDescription(v string) *ActionUpsert {
	u.Set(action.FieldDescription, v)
	return u
}

// UpdateDescription sets the "description" field to the value that was provided on create.
func (u *ActionUpsert) UpdateDescription() *ActionUpsert {
	u.SetExcluded(action.FieldDescription)
	return u
}

// ClearDescription clears the value of the "description" field.
func (u *ActionUpsert) ClearDescription() *ActionUpsert {
	u.SetNull(action.FieldDescription)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.Action.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(action.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *ActionUpsertOne) UpdateNewValues() *ActionUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(action.FieldID)
		}
		if _, exists := u.create.mutation.CreatedAt(); exists {
			s.SetIgnore(action.FieldCreatedAt)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Action.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *ActionUpsertOne) Ignore() *ActionUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *ActionUpsertOne) DoNothing() *ActionUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the ActionCreate.OnConflict
// documentation for more info.
func (u *ActionUpsertOne) Update(set func(*ActionUpsert)) *ActionUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&ActionUpsert{UpdateSet: update})
	}))
	return u
}

// SetUpdatedAt sets the "updated_at" field.
func (u *ActionUpsertOne) SetUpdatedAt(v time.Time) *ActionUpsertOne {
	return u.Update(func(s *ActionUpsert) {
		s.SetUpdatedAt(v)
	})
}

// UpdateUpdatedAt sets the "updated_at" field to the value that was provided on create.
func (u *ActionUpsertOne) UpdateUpdatedAt() *ActionUpsertOne {
	return u.Update(func(s *ActionUpsert) {
		s.UpdateUpdatedAt()
	})
}

// SetName sets the "name" field.
func (u *ActionUpsertOne) SetName(v string) *ActionUpsertOne {
	return u.Update(func(s *ActionUpsert) {
		s.SetName(v)
	})
}

// UpdateName sets the "name" field to the value that was provided on create.
func (u *ActionUpsertOne) UpdateName() *ActionUpsertOne {
	return u.Update(func(s *ActionUpsert) {
		s.UpdateName()
	})
}

// SetDescription sets the "description" field.
func (u *ActionUpsertOne) SetDescription(v string) *ActionUpsertOne {
	return u.Update(func(s *ActionUpsert) {
		s.SetDescription(v)
	})
}

// UpdateDescription sets the "description" field to the value that was provided on create.
func (u *ActionUpsertOne) UpdateDescription() *ActionUpsertOne {
	return u.Update(func(s *ActionUpsert) {
		s.UpdateDescription()
	})
}

// ClearDescription clears the value of the "description" field.
func (u *ActionUpsertOne) ClearDescription() *ActionUpsertOne {
	return u.Update(func(s *ActionUpsert) {
		s.ClearDescription()
	})
}

// Exec executes the query.
func (u *ActionUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for ActionCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *ActionUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *ActionUpsertOne) ID(ctx context.Context) (id uint64, err error) {
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *ActionUpsertOne) IDX(ctx context.Context) uint64 {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// ActionCreateBulk is the builder for creating many Action entities in bulk.
type ActionCreateBulk struct {
	config
	err      error
	builders []*ActionCreate
	conflict []sql.ConflictOption
}

// Save creates the Action entities in the database.
func (acb *ActionCreateBulk) Save(ctx context.Context) ([]*Action, error) {
	if acb.err != nil {
		return nil, acb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(acb.builders))
	nodes := make([]*Action, len(acb.builders))
	mutators := make([]Mutator, len(acb.builders))
	for i := range acb.builders {
		func(i int, root context.Context) {
			builder := acb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*ActionMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, acb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = acb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, acb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil && nodes[i].ID == 0 {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = uint64(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, acb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (acb *ActionCreateBulk) SaveX(ctx context.Context) []*Action {
	v, err := acb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (acb *ActionCreateBulk) Exec(ctx context.Context) error {
	_, err := acb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (acb *ActionCreateBulk) ExecX(ctx context.Context) {
	if err := acb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Action.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.ActionUpsert) {
//			SetCreatedAt(v+v).
//		}).
//		Exec(ctx)
func (acb *ActionCreateBulk) OnConflict(opts ...sql.ConflictOption) *ActionUpsertBulk {
	acb.conflict = opts
	return &ActionUpsertBulk{
		create: acb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Action.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (acb *ActionCreateBulk) OnConflictColumns(columns ...string) *ActionUpsertBulk {
	acb.conflict = append(acb.conflict, sql.ConflictColumns(columns...))
	return &ActionUpsertBulk{
		create: acb,
	}
}

// ActionUpsertBulk is the builder for "upsert"-ing
// a bulk of Action nodes.
type ActionUpsertBulk struct {
	create *ActionCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.Action.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(action.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *ActionUpsertBulk) UpdateNewValues() *ActionUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(action.FieldID)
			}
			if _, exists := b.mutation.CreatedAt(); exists {
				s.SetIgnore(action.FieldCreatedAt)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Action.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *ActionUpsertBulk) Ignore() *ActionUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *ActionUpsertBulk) DoNothing() *ActionUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the ActionCreateBulk.OnConflict
// documentation for more info.
func (u *ActionUpsertBulk) Update(set func(*ActionUpsert)) *ActionUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&ActionUpsert{UpdateSet: update})
	}))
	return u
}

// SetUpdatedAt sets the "updated_at" field.
func (u *ActionUpsertBulk) SetUpdatedAt(v time.Time) *ActionUpsertBulk {
	return u.Update(func(s *ActionUpsert) {
		s.SetUpdatedAt(v)
	})
}

// UpdateUpdatedAt sets the "updated_at" field to the value that was provided on create.
func (u *ActionUpsertBulk) UpdateUpdatedAt() *ActionUpsertBulk {
	return u.Update(func(s *ActionUpsert) {
		s.UpdateUpdatedAt()
	})
}

// SetName sets the "name" field.
func (u *ActionUpsertBulk) SetName(v string) *ActionUpsertBulk {
	return u.Update(func(s *ActionUpsert) {
		s.SetName(v)
	})
}

// UpdateName sets the "name" field to the value that was provided on create.
func (u *ActionUpsertBulk) UpdateName() *ActionUpsertBulk {
	return u.Update(func(s *ActionUpsert) {
		s.UpdateName()
	})
}

// SetDescription sets the "description" field.
func (u *ActionUpsertBulk) SetDescription(v string) *ActionUpsertBulk {
	return u.Update(func(s *ActionUpsert) {
		s.SetDescription(v)
	})
}

// UpdateDescription sets the "description" field to the value that was provided on create.
func (u *ActionUpsertBulk) UpdateDescription() *ActionUpsertBulk {
	return u.Update(func(s *ActionUpsert) {
		s.UpdateDescription()
	})
}

// ClearDescription clears the value of the "description" field.
func (u *ActionUpsertBulk) ClearDescription() *ActionUpsertBulk {
	return u.Update(func(s *ActionUpsert) {
		s.ClearDescription()
	})
}

// Exec executes the query.
func (u *ActionUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the ActionCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for ActionCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *ActionUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}