package config

import (
	"github.com/spf13/viper"
)

// Config Struct that maps the YAML structure
type Config struct {
	Server struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"server"`

	Redis struct {
		Address   string `mapstructure:"address"`
		Namespace string `mapstructure:"namespace"`
	} `mapstructure:"redis"`

	Google struct {
		ClientID string `mapstructure:"client_id"`
	} `mapstructure:"google"`

	Database struct {
		Host     string `mapstructure:"host"`
		Name     string `mapstructure:"name"`
		Username string `mapstructure:"username"`
		Port     string `mapstructure:"port"`
		Password string `mapstructure:"password"`
	} `mapstructure:"database"`
	Auth struct {
		AccessKey  string `mapstructure:"access_key"`
		RefreshKey string `mapstructure:"refresh_key"`
		AccessExp  int    `mapstructure:"access_expires"`
		RefreshExp int    `mapstructure:"refresh_expires"`
	} `mapstructure:"auth"`
}

func ReadConfig(path string) (Config, error) {
	var cfg Config

	// Thiết lập để tự động đọc biến môi trường
	viper.AutomaticEnv()

	// Đọc file cấu hình
	viper.SetConfigFile(path)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// Map for database
	viper.BindEnv("database.host", "DATABASE_HOST")
	viper.BindEnv("database.name", "DATABASE_NAME")
	viper.BindEnv("database.username", "DATABASE_USERNAME")
	viper.BindEnv("database.password", "DATABASE_PASSWORD")

	// Map for jwt secret
	viper.BindEnv("auth.access_key", "AUTH_ACCESS_KEY")
	viper.BindEnv("auth.refesh_key", "AUTH_REFESH_KEY")

	viper.BindEnv("redis.address", "REDIS_ADDRESS")
	viper.BindEnv("redis.namespace", "REDIS_NAMESPACE")

	// Map for google
	viper.BindEnv("google.client_id", "GOOGLE_CLIENT_ID")

	if err := viper.Unmarshal(&cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}
