// Code generated by ent, DO NOT EDIT.

package ent

import (
	"bulbasaur/package/ent/action"
	"bulbasaur/package/ent/permission"
	"bulbasaur/package/ent/role"
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
)

// PermissionCreate is the builder for creating a Permission entity.
type PermissionCreate struct {
	config
	mutation *PermissionMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetActionID sets the "action_id" field.
func (pc *PermissionCreate) SetActionID(u uint64) *PermissionCreate {
	pc.mutation.SetActionID(u)
	return pc
}

// SetRoleID sets the "role_id" field.
func (pc *PermissionCreate) SetRoleID(u uint64) *PermissionCreate {
	pc.mutation.SetRoleID(u)
	return pc
}

// SetAction sets the "action" edge to the Action entity.
func (pc *PermissionCreate) SetAction(a *Action) *PermissionCreate {
	return pc.SetActionID(a.ID)
}

// SetRole sets the "role" edge to the Role entity.
func (pc *PermissionCreate) SetRole(r *Role) *PermissionCreate {
	return pc.SetRoleID(r.ID)
}

// Mutation returns the PermissionMutation object of the builder.
func (pc *PermissionCreate) Mutation() *PermissionMutation {
	return pc.mutation
}

// Save creates the Permission in the database.
func (pc *PermissionCreate) Save(ctx context.Context) (*Permission, error) {
	return withHooks(ctx, pc.sqlSave, pc.mutation, pc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (pc *PermissionCreate) SaveX(ctx context.Context) *Permission {
	v, err := pc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (pc *PermissionCreate) Exec(ctx context.Context) error {
	_, err := pc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pc *PermissionCreate) ExecX(ctx context.Context) {
	if err := pc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pc *PermissionCreate) check() error {
	if _, ok := pc.mutation.ActionID(); !ok {
		return &ValidationError{Name: "action_id", err: errors.New(`ent: missing required field "Permission.action_id"`)}
	}
	if _, ok := pc.mutation.RoleID(); !ok {
		return &ValidationError{Name: "role_id", err: errors.New(`ent: missing required field "Permission.role_id"`)}
	}
	if len(pc.mutation.ActionIDs()) == 0 {
		return &ValidationError{Name: "action", err: errors.New(`ent: missing required edge "Permission.action"`)}
	}
	if len(pc.mutation.RoleIDs()) == 0 {
		return &ValidationError{Name: "role", err: errors.New(`ent: missing required edge "Permission.role"`)}
	}
	return nil
}

func (pc *PermissionCreate) sqlSave(ctx context.Context) (*Permission, error) {
	if err := pc.check(); err != nil {
		return nil, err
	}
	_node, _spec := pc.createSpec()
	if err := sqlgraph.CreateNode(ctx, pc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	pc.mutation.id = &_node.ID
	pc.mutation.done = true
	return _node, nil
}

func (pc *PermissionCreate) createSpec() (*Permission, *sqlgraph.CreateSpec) {
	var (
		_node = &Permission{config: pc.config}
		_spec = sqlgraph.NewCreateSpec(permission.Table, sqlgraph.NewFieldSpec(permission.FieldID, field.TypeInt))
	)
	_spec.OnConflict = pc.conflict
	if nodes := pc.mutation.ActionIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   permission.ActionTable,
			Columns: []string{permission.ActionColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(action.FieldID, field.TypeUint64),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.ActionID = nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pc.mutation.RoleIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   permission.RoleTable,
			Columns: []string{permission.RoleColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(role.FieldID, field.TypeUint64),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.RoleID = nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Permission.Create().
//		SetActionID(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.PermissionUpsert) {
//			SetActionID(v+v).
//		}).
//		Exec(ctx)
func (pc *PermissionCreate) OnConflict(opts ...sql.ConflictOption) *PermissionUpsertOne {
	pc.conflict = opts
	return &PermissionUpsertOne{
		create: pc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Permission.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (pc *PermissionCreate) OnConflictColumns(columns ...string) *PermissionUpsertOne {
	pc.conflict = append(pc.conflict, sql.ConflictColumns(columns...))
	return &PermissionUpsertOne{
		create: pc,
	}
}

type (
	// PermissionUpsertOne is the builder for "upsert"-ing
	//  one Permission node.
	PermissionUpsertOne struct {
		create *PermissionCreate
	}

	// PermissionUpsert is the "OnConflict" setter.
	PermissionUpsert struct {
		*sql.UpdateSet
	}
)

// SetActionID sets the "action_id" field.
func (u *PermissionUpsert) SetActionID(v uint64) *PermissionUpsert {
	u.Set(permission.FieldActionID, v)
	return u
}

// UpdateActionID sets the "action_id" field to the value that was provided on create.
func (u *PermissionUpsert) UpdateActionID() *PermissionUpsert {
	u.SetExcluded(permission.FieldActionID)
	return u
}

// SetRoleID sets the "role_id" field.
func (u *PermissionUpsert) SetRoleID(v uint64) *PermissionUpsert {
	u.Set(permission.FieldRoleID, v)
	return u
}

// UpdateRoleID sets the "role_id" field to the value that was provided on create.
func (u *PermissionUpsert) UpdateRoleID() *PermissionUpsert {
	u.SetExcluded(permission.FieldRoleID)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create.
// Using this option is equivalent to using:
//
//	client.Permission.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//		).
//		Exec(ctx)
func (u *PermissionUpsertOne) UpdateNewValues() *PermissionUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Permission.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *PermissionUpsertOne) Ignore() *PermissionUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *PermissionUpsertOne) DoNothing() *PermissionUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the PermissionCreate.OnConflict
// documentation for more info.
func (u *PermissionUpsertOne) Update(set func(*PermissionUpsert)) *PermissionUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&PermissionUpsert{UpdateSet: update})
	}))
	return u
}

// SetActionID sets the "action_id" field.
func (u *PermissionUpsertOne) SetActionID(v uint64) *PermissionUpsertOne {
	return u.Update(func(s *PermissionUpsert) {
		s.SetActionID(v)
	})
}

// UpdateActionID sets the "action_id" field to the value that was provided on create.
func (u *PermissionUpsertOne) UpdateActionID() *PermissionUpsertOne {
	return u.Update(func(s *PermissionUpsert) {
		s.UpdateActionID()
	})
}

// SetRoleID sets the "role_id" field.
func (u *PermissionUpsertOne) SetRoleID(v uint64) *PermissionUpsertOne {
	return u.Update(func(s *PermissionUpsert) {
		s.SetRoleID(v)
	})
}

// UpdateRoleID sets the "role_id" field to the value that was provided on create.
func (u *PermissionUpsertOne) UpdateRoleID() *PermissionUpsertOne {
	return u.Update(func(s *PermissionUpsert) {
		s.UpdateRoleID()
	})
}

// Exec executes the query.
func (u *PermissionUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for PermissionCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *PermissionUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *PermissionUpsertOne) ID(ctx context.Context) (id int, err error) {
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *PermissionUpsertOne) IDX(ctx context.Context) int {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// PermissionCreateBulk is the builder for creating many Permission entities in bulk.
type PermissionCreateBulk struct {
	config
	err      error
	builders []*PermissionCreate
	conflict []sql.ConflictOption
}

// Save creates the Permission entities in the database.
func (pcb *PermissionCreateBulk) Save(ctx context.Context) ([]*Permission, error) {
	if pcb.err != nil {
		return nil, pcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(pcb.builders))
	nodes := make([]*Permission, len(pcb.builders))
	mutators := make([]Mutator, len(pcb.builders))
	for i := range pcb.builders {
		func(i int, root context.Context) {
			builder := pcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*PermissionMutation)
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
					_, err = mutators[i+1].Mutate(root, pcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = pcb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, pcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
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
		if _, err := mutators[0].Mutate(ctx, pcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (pcb *PermissionCreateBulk) SaveX(ctx context.Context) []*Permission {
	v, err := pcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (pcb *PermissionCreateBulk) Exec(ctx context.Context) error {
	_, err := pcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pcb *PermissionCreateBulk) ExecX(ctx context.Context) {
	if err := pcb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Permission.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.PermissionUpsert) {
//			SetActionID(v+v).
//		}).
//		Exec(ctx)
func (pcb *PermissionCreateBulk) OnConflict(opts ...sql.ConflictOption) *PermissionUpsertBulk {
	pcb.conflict = opts
	return &PermissionUpsertBulk{
		create: pcb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Permission.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (pcb *PermissionCreateBulk) OnConflictColumns(columns ...string) *PermissionUpsertBulk {
	pcb.conflict = append(pcb.conflict, sql.ConflictColumns(columns...))
	return &PermissionUpsertBulk{
		create: pcb,
	}
}

// PermissionUpsertBulk is the builder for "upsert"-ing
// a bulk of Permission nodes.
type PermissionUpsertBulk struct {
	create *PermissionCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.Permission.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//		).
//		Exec(ctx)
func (u *PermissionUpsertBulk) UpdateNewValues() *PermissionUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Permission.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *PermissionUpsertBulk) Ignore() *PermissionUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *PermissionUpsertBulk) DoNothing() *PermissionUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the PermissionCreateBulk.OnConflict
// documentation for more info.
func (u *PermissionUpsertBulk) Update(set func(*PermissionUpsert)) *PermissionUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&PermissionUpsert{UpdateSet: update})
	}))
	return u
}

// SetActionID sets the "action_id" field.
func (u *PermissionUpsertBulk) SetActionID(v uint64) *PermissionUpsertBulk {
	return u.Update(func(s *PermissionUpsert) {
		s.SetActionID(v)
	})
}

// UpdateActionID sets the "action_id" field to the value that was provided on create.
func (u *PermissionUpsertBulk) UpdateActionID() *PermissionUpsertBulk {
	return u.Update(func(s *PermissionUpsert) {
		s.UpdateActionID()
	})
}

// SetRoleID sets the "role_id" field.
func (u *PermissionUpsertBulk) SetRoleID(v uint64) *PermissionUpsertBulk {
	return u.Update(func(s *PermissionUpsert) {
		s.SetRoleID(v)
	})
}

// UpdateRoleID sets the "role_id" field to the value that was provided on create.
func (u *PermissionUpsertBulk) UpdateRoleID() *PermissionUpsertBulk {
	return u.Update(func(s *PermissionUpsert) {
		s.UpdateRoleID()
	})
}

// Exec executes the query.
func (u *PermissionUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the PermissionCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for PermissionCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *PermissionUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}