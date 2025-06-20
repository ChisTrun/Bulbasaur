// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// GooglesColumns holds the columns for the "googles" table.
	GooglesColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUint64, Increment: true},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "updated_at", Type: field.TypeTime},
		{Name: "tenant_id", Type: field.TypeString},
		{Name: "email", Type: field.TypeString},
		{Name: "user_id", Type: field.TypeUint64, Unique: true},
	}
	// GooglesTable holds the schema information for the "googles" table.
	GooglesTable = &schema.Table{
		Name:       "googles",
		Columns:    GooglesColumns,
		PrimaryKey: []*schema.Column{GooglesColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "googles_users_google",
				Columns:    []*schema.Column{GooglesColumns[5]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.Cascade,
			},
		},
		Indexes: []*schema.Index{
			{
				Name:    "google_tenant_id_email",
				Unique:  true,
				Columns: []*schema.Column{GooglesColumns[3], GooglesColumns[4]},
			},
		},
	}
	// LocalsColumns holds the columns for the "locals" table.
	LocalsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUint64, Increment: true},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "updated_at", Type: field.TypeTime},
		{Name: "tenant_id", Type: field.TypeString},
		{Name: "username", Type: field.TypeString, Nullable: true},
		{Name: "password", Type: field.TypeString, Nullable: true},
		{Name: "user_id", Type: field.TypeUint64, Unique: true},
	}
	// LocalsTable holds the schema information for the "locals" table.
	LocalsTable = &schema.Table{
		Name:       "locals",
		Columns:    LocalsColumns,
		PrimaryKey: []*schema.Column{LocalsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "locals_users_local",
				Columns:    []*schema.Column{LocalsColumns[6]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.Cascade,
			},
		},
		Indexes: []*schema.Index{
			{
				Name:    "local_tenant_id_username",
				Unique:  true,
				Columns: []*schema.Column{LocalsColumns[3], LocalsColumns[4]},
			},
		},
	}
	// TransactionHistoriesColumns holds the columns for the "transaction_histories" table.
	TransactionHistoriesColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUint64, Increment: true},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "updated_at", Type: field.TypeTime},
		{Name: "user_id", Type: field.TypeUint64},
		{Name: "amount", Type: field.TypeFloat64},
		{Name: "note", Type: field.TypeString},
	}
	// TransactionHistoriesTable holds the schema information for the "transaction_histories" table.
	TransactionHistoriesTable = &schema.Table{
		Name:       "transaction_histories",
		Columns:    TransactionHistoriesColumns,
		PrimaryKey: []*schema.Column{TransactionHistoriesColumns[0]},
	}
	// UsersColumns holds the columns for the "users" table.
	UsersColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUint64, Increment: true},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "updated_at", Type: field.TypeTime},
		{Name: "tenant_id", Type: field.TypeString},
		{Name: "safe_id", Type: field.TypeString, Default: "104fbe04-4684-4e99-832b-58f64e90650c"},
		{Name: "email", Type: field.TypeString, Nullable: true},
		{Name: "metadata", Type: field.TypeJSON, Nullable: true},
		{Name: "last_signed_in", Type: field.TypeTime, Nullable: true},
		{Name: "role", Type: field.TypeInt32},
		{Name: "balance", Type: field.TypeFloat64, Default: 0},
		{Name: "is_premium", Type: field.TypeBool, Default: false},
		{Name: "premium_expires", Type: field.TypeTime, Nullable: true},
	}
	// UsersTable holds the schema information for the "users" table.
	UsersTable = &schema.Table{
		Name:       "users",
		Columns:    UsersColumns,
		PrimaryKey: []*schema.Column{UsersColumns[0]},
		Indexes: []*schema.Index{
			{
				Name:    "user_tenant_id_id",
				Unique:  true,
				Columns: []*schema.Column{UsersColumns[3], UsersColumns[0]},
			},
			{
				Name:    "user_safe_id",
				Unique:  true,
				Columns: []*schema.Column{UsersColumns[4]},
			},
		},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		GooglesTable,
		LocalsTable,
		TransactionHistoriesTable,
		UsersTable,
	}
)

func init() {
	GooglesTable.ForeignKeys[0].RefTable = UsersTable
	LocalsTable.ForeignKeys[0].RefTable = UsersTable
}
