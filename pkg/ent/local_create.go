// Code generated by ent, DO NOT EDIT.

package ent

import (
	"bulbasaur/pkg/ent/local"
	"bulbasaur/pkg/ent/user"
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
)

// LocalCreate is the builder for creating a Local entity.
type LocalCreate struct {
	config
	mutation *LocalMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetCreatedAt sets the "created_at" field.
func (lc *LocalCreate) SetCreatedAt(t time.Time) *LocalCreate {
	lc.mutation.SetCreatedAt(t)
	return lc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (lc *LocalCreate) SetNillableCreatedAt(t *time.Time) *LocalCreate {
	if t != nil {
		lc.SetCreatedAt(*t)
	}
	return lc
}

// SetUpdatedAt sets the "updated_at" field.
func (lc *LocalCreate) SetUpdatedAt(t time.Time) *LocalCreate {
	lc.mutation.SetUpdatedAt(t)
	return lc
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (lc *LocalCreate) SetNillableUpdatedAt(t *time.Time) *LocalCreate {
	if t != nil {
		lc.SetUpdatedAt(*t)
	}
	return lc
}

// SetTenantID sets the "tenant_id" field.
func (lc *LocalCreate) SetTenantID(s string) *LocalCreate {
	lc.mutation.SetTenantID(s)
	return lc
}

// SetUserID sets the "user_id" field.
func (lc *LocalCreate) SetUserID(u uint64) *LocalCreate {
	lc.mutation.SetUserID(u)
	return lc
}

// SetUsername sets the "username" field.
func (lc *LocalCreate) SetUsername(s string) *LocalCreate {
	lc.mutation.SetUsername(s)
	return lc
}

// SetNillableUsername sets the "username" field if the given value is not nil.
func (lc *LocalCreate) SetNillableUsername(s *string) *LocalCreate {
	if s != nil {
		lc.SetUsername(*s)
	}
	return lc
}

// SetPassword sets the "password" field.
func (lc *LocalCreate) SetPassword(s string) *LocalCreate {
	lc.mutation.SetPassword(s)
	return lc
}

// SetNillablePassword sets the "password" field if the given value is not nil.
func (lc *LocalCreate) SetNillablePassword(s *string) *LocalCreate {
	if s != nil {
		lc.SetPassword(*s)
	}
	return lc
}

// SetID sets the "id" field.
func (lc *LocalCreate) SetID(u uint64) *LocalCreate {
	lc.mutation.SetID(u)
	return lc
}

// SetUser sets the "user" edge to the User entity.
func (lc *LocalCreate) SetUser(u *User) *LocalCreate {
	return lc.SetUserID(u.ID)
}

// Mutation returns the LocalMutation object of the builder.
func (lc *LocalCreate) Mutation() *LocalMutation {
	return lc.mutation
}

// Save creates the Local in the database.
func (lc *LocalCreate) Save(ctx context.Context) (*Local, error) {
	lc.defaults()
	return withHooks(ctx, lc.sqlSave, lc.mutation, lc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (lc *LocalCreate) SaveX(ctx context.Context) *Local {
	v, err := lc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (lc *LocalCreate) Exec(ctx context.Context) error {
	_, err := lc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (lc *LocalCreate) ExecX(ctx context.Context) {
	if err := lc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (lc *LocalCreate) defaults() {
	if _, ok := lc.mutation.CreatedAt(); !ok {
		v := local.DefaultCreatedAt()
		lc.mutation.SetCreatedAt(v)
	}
	if _, ok := lc.mutation.UpdatedAt(); !ok {
		v := local.DefaultUpdatedAt()
		lc.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (lc *LocalCreate) check() error {
	if _, ok := lc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "Local.created_at"`)}
	}
	if _, ok := lc.mutation.UpdatedAt(); !ok {
		return &ValidationError{Name: "updated_at", err: errors.New(`ent: missing required field "Local.updated_at"`)}
	}
	if _, ok := lc.mutation.TenantID(); !ok {
		return &ValidationError{Name: "tenant_id", err: errors.New(`ent: missing required field "Local.tenant_id"`)}
	}
	if _, ok := lc.mutation.UserID(); !ok {
		return &ValidationError{Name: "user_id", err: errors.New(`ent: missing required field "Local.user_id"`)}
	}
	if len(lc.mutation.UserIDs()) == 0 {
		return &ValidationError{Name: "user", err: errors.New(`ent: missing required edge "Local.user"`)}
	}
	return nil
}

func (lc *LocalCreate) sqlSave(ctx context.Context) (*Local, error) {
	if err := lc.check(); err != nil {
		return nil, err
	}
	_node, _spec := lc.createSpec()
	if err := sqlgraph.CreateNode(ctx, lc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != _node.ID {
		id := _spec.ID.Value.(int64)
		_node.ID = uint64(id)
	}
	lc.mutation.id = &_node.ID
	lc.mutation.done = true
	return _node, nil
}

func (lc *LocalCreate) createSpec() (*Local, *sqlgraph.CreateSpec) {
	var (
		_node = &Local{config: lc.config}
		_spec = sqlgraph.NewCreateSpec(local.Table, sqlgraph.NewFieldSpec(local.FieldID, field.TypeUint64))
	)
	_spec.OnConflict = lc.conflict
	if id, ok := lc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := lc.mutation.CreatedAt(); ok {
		_spec.SetField(local.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := lc.mutation.UpdatedAt(); ok {
		_spec.SetField(local.FieldUpdatedAt, field.TypeTime, value)
		_node.UpdatedAt = value
	}
	if value, ok := lc.mutation.TenantID(); ok {
		_spec.SetField(local.FieldTenantID, field.TypeString, value)
		_node.TenantID = value
	}
	if value, ok := lc.mutation.Username(); ok {
		_spec.SetField(local.FieldUsername, field.TypeString, value)
		_node.Username = value
	}
	if value, ok := lc.mutation.Password(); ok {
		_spec.SetField(local.FieldPassword, field.TypeString, value)
		_node.Password = value
	}
	if nodes := lc.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   local.UserTable,
			Columns: []string{local.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUint64),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.UserID = nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Local.Create().
//		SetCreatedAt(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.LocalUpsert) {
//			SetCreatedAt(v+v).
//		}).
//		Exec(ctx)
func (lc *LocalCreate) OnConflict(opts ...sql.ConflictOption) *LocalUpsertOne {
	lc.conflict = opts
	return &LocalUpsertOne{
		create: lc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Local.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (lc *LocalCreate) OnConflictColumns(columns ...string) *LocalUpsertOne {
	lc.conflict = append(lc.conflict, sql.ConflictColumns(columns...))
	return &LocalUpsertOne{
		create: lc,
	}
}

type (
	// LocalUpsertOne is the builder for "upsert"-ing
	//  one Local node.
	LocalUpsertOne struct {
		create *LocalCreate
	}

	// LocalUpsert is the "OnConflict" setter.
	LocalUpsert struct {
		*sql.UpdateSet
	}
)

// SetUpdatedAt sets the "updated_at" field.
func (u *LocalUpsert) SetUpdatedAt(v time.Time) *LocalUpsert {
	u.Set(local.FieldUpdatedAt, v)
	return u
}

// UpdateUpdatedAt sets the "updated_at" field to the value that was provided on create.
func (u *LocalUpsert) UpdateUpdatedAt() *LocalUpsert {
	u.SetExcluded(local.FieldUpdatedAt)
	return u
}

// SetTenantID sets the "tenant_id" field.
func (u *LocalUpsert) SetTenantID(v string) *LocalUpsert {
	u.Set(local.FieldTenantID, v)
	return u
}

// UpdateTenantID sets the "tenant_id" field to the value that was provided on create.
func (u *LocalUpsert) UpdateTenantID() *LocalUpsert {
	u.SetExcluded(local.FieldTenantID)
	return u
}

// SetUserID sets the "user_id" field.
func (u *LocalUpsert) SetUserID(v uint64) *LocalUpsert {
	u.Set(local.FieldUserID, v)
	return u
}

// UpdateUserID sets the "user_id" field to the value that was provided on create.
func (u *LocalUpsert) UpdateUserID() *LocalUpsert {
	u.SetExcluded(local.FieldUserID)
	return u
}

// SetUsername sets the "username" field.
func (u *LocalUpsert) SetUsername(v string) *LocalUpsert {
	u.Set(local.FieldUsername, v)
	return u
}

// UpdateUsername sets the "username" field to the value that was provided on create.
func (u *LocalUpsert) UpdateUsername() *LocalUpsert {
	u.SetExcluded(local.FieldUsername)
	return u
}

// ClearUsername clears the value of the "username" field.
func (u *LocalUpsert) ClearUsername() *LocalUpsert {
	u.SetNull(local.FieldUsername)
	return u
}

// SetPassword sets the "password" field.
func (u *LocalUpsert) SetPassword(v string) *LocalUpsert {
	u.Set(local.FieldPassword, v)
	return u
}

// UpdatePassword sets the "password" field to the value that was provided on create.
func (u *LocalUpsert) UpdatePassword() *LocalUpsert {
	u.SetExcluded(local.FieldPassword)
	return u
}

// ClearPassword clears the value of the "password" field.
func (u *LocalUpsert) ClearPassword() *LocalUpsert {
	u.SetNull(local.FieldPassword)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.Local.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(local.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *LocalUpsertOne) UpdateNewValues() *LocalUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(local.FieldID)
		}
		if _, exists := u.create.mutation.CreatedAt(); exists {
			s.SetIgnore(local.FieldCreatedAt)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Local.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *LocalUpsertOne) Ignore() *LocalUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *LocalUpsertOne) DoNothing() *LocalUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the LocalCreate.OnConflict
// documentation for more info.
func (u *LocalUpsertOne) Update(set func(*LocalUpsert)) *LocalUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&LocalUpsert{UpdateSet: update})
	}))
	return u
}

// SetUpdatedAt sets the "updated_at" field.
func (u *LocalUpsertOne) SetUpdatedAt(v time.Time) *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.SetUpdatedAt(v)
	})
}

// UpdateUpdatedAt sets the "updated_at" field to the value that was provided on create.
func (u *LocalUpsertOne) UpdateUpdatedAt() *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.UpdateUpdatedAt()
	})
}

// SetTenantID sets the "tenant_id" field.
func (u *LocalUpsertOne) SetTenantID(v string) *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.SetTenantID(v)
	})
}

// UpdateTenantID sets the "tenant_id" field to the value that was provided on create.
func (u *LocalUpsertOne) UpdateTenantID() *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.UpdateTenantID()
	})
}

// SetUserID sets the "user_id" field.
func (u *LocalUpsertOne) SetUserID(v uint64) *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.SetUserID(v)
	})
}

// UpdateUserID sets the "user_id" field to the value that was provided on create.
func (u *LocalUpsertOne) UpdateUserID() *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.UpdateUserID()
	})
}

// SetUsername sets the "username" field.
func (u *LocalUpsertOne) SetUsername(v string) *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.SetUsername(v)
	})
}

// UpdateUsername sets the "username" field to the value that was provided on create.
func (u *LocalUpsertOne) UpdateUsername() *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.UpdateUsername()
	})
}

// ClearUsername clears the value of the "username" field.
func (u *LocalUpsertOne) ClearUsername() *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.ClearUsername()
	})
}

// SetPassword sets the "password" field.
func (u *LocalUpsertOne) SetPassword(v string) *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.SetPassword(v)
	})
}

// UpdatePassword sets the "password" field to the value that was provided on create.
func (u *LocalUpsertOne) UpdatePassword() *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.UpdatePassword()
	})
}

// ClearPassword clears the value of the "password" field.
func (u *LocalUpsertOne) ClearPassword() *LocalUpsertOne {
	return u.Update(func(s *LocalUpsert) {
		s.ClearPassword()
	})
}

// Exec executes the query.
func (u *LocalUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for LocalCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *LocalUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *LocalUpsertOne) ID(ctx context.Context) (id uint64, err error) {
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *LocalUpsertOne) IDX(ctx context.Context) uint64 {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// LocalCreateBulk is the builder for creating many Local entities in bulk.
type LocalCreateBulk struct {
	config
	err      error
	builders []*LocalCreate
	conflict []sql.ConflictOption
}

// Save creates the Local entities in the database.
func (lcb *LocalCreateBulk) Save(ctx context.Context) ([]*Local, error) {
	if lcb.err != nil {
		return nil, lcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(lcb.builders))
	nodes := make([]*Local, len(lcb.builders))
	mutators := make([]Mutator, len(lcb.builders))
	for i := range lcb.builders {
		func(i int, root context.Context) {
			builder := lcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*LocalMutation)
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
					_, err = mutators[i+1].Mutate(root, lcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = lcb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, lcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, lcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (lcb *LocalCreateBulk) SaveX(ctx context.Context) []*Local {
	v, err := lcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (lcb *LocalCreateBulk) Exec(ctx context.Context) error {
	_, err := lcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (lcb *LocalCreateBulk) ExecX(ctx context.Context) {
	if err := lcb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Local.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.LocalUpsert) {
//			SetCreatedAt(v+v).
//		}).
//		Exec(ctx)
func (lcb *LocalCreateBulk) OnConflict(opts ...sql.ConflictOption) *LocalUpsertBulk {
	lcb.conflict = opts
	return &LocalUpsertBulk{
		create: lcb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Local.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (lcb *LocalCreateBulk) OnConflictColumns(columns ...string) *LocalUpsertBulk {
	lcb.conflict = append(lcb.conflict, sql.ConflictColumns(columns...))
	return &LocalUpsertBulk{
		create: lcb,
	}
}

// LocalUpsertBulk is the builder for "upsert"-ing
// a bulk of Local nodes.
type LocalUpsertBulk struct {
	create *LocalCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.Local.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(local.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *LocalUpsertBulk) UpdateNewValues() *LocalUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(local.FieldID)
			}
			if _, exists := b.mutation.CreatedAt(); exists {
				s.SetIgnore(local.FieldCreatedAt)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Local.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *LocalUpsertBulk) Ignore() *LocalUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *LocalUpsertBulk) DoNothing() *LocalUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the LocalCreateBulk.OnConflict
// documentation for more info.
func (u *LocalUpsertBulk) Update(set func(*LocalUpsert)) *LocalUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&LocalUpsert{UpdateSet: update})
	}))
	return u
}

// SetUpdatedAt sets the "updated_at" field.
func (u *LocalUpsertBulk) SetUpdatedAt(v time.Time) *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.SetUpdatedAt(v)
	})
}

// UpdateUpdatedAt sets the "updated_at" field to the value that was provided on create.
func (u *LocalUpsertBulk) UpdateUpdatedAt() *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.UpdateUpdatedAt()
	})
}

// SetTenantID sets the "tenant_id" field.
func (u *LocalUpsertBulk) SetTenantID(v string) *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.SetTenantID(v)
	})
}

// UpdateTenantID sets the "tenant_id" field to the value that was provided on create.
func (u *LocalUpsertBulk) UpdateTenantID() *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.UpdateTenantID()
	})
}

// SetUserID sets the "user_id" field.
func (u *LocalUpsertBulk) SetUserID(v uint64) *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.SetUserID(v)
	})
}

// UpdateUserID sets the "user_id" field to the value that was provided on create.
func (u *LocalUpsertBulk) UpdateUserID() *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.UpdateUserID()
	})
}

// SetUsername sets the "username" field.
func (u *LocalUpsertBulk) SetUsername(v string) *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.SetUsername(v)
	})
}

// UpdateUsername sets the "username" field to the value that was provided on create.
func (u *LocalUpsertBulk) UpdateUsername() *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.UpdateUsername()
	})
}

// ClearUsername clears the value of the "username" field.
func (u *LocalUpsertBulk) ClearUsername() *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.ClearUsername()
	})
}

// SetPassword sets the "password" field.
func (u *LocalUpsertBulk) SetPassword(v string) *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.SetPassword(v)
	})
}

// UpdatePassword sets the "password" field to the value that was provided on create.
func (u *LocalUpsertBulk) UpdatePassword() *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.UpdatePassword()
	})
}

// ClearPassword clears the value of the "password" field.
func (u *LocalUpsertBulk) ClearPassword() *LocalUpsertBulk {
	return u.Update(func(s *LocalUpsert) {
		s.ClearPassword()
	})
}

// Exec executes the query.
func (u *LocalUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the LocalCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for LocalCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *LocalUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
