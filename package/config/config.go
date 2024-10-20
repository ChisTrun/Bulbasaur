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
	Database struct {
		Host     string `mapstructure:"host"`
		Name     string `mapstructure:"name"`
		Username string `mapstructure:"username"`
		Port     string `mapstructure:"port"`
		Password string `mapstructure:"password"`
	} `mapstructure:"database"`
	Auth struct {
		AccessKey string `mapstructure:"access_key"`
		RefeshKey string `mapstructure:"refesh_key"`
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

	viper.BindEnv("database.host", "DATABASE_HOST")
	viper.BindEnv("database.name", "DATABASE_NAME")
	viper.BindEnv("database.username", "DATABASE_USERNAME")
	viper.BindEnv("database.password", "DATABASE_PASSWORD")

	viper.BindEnv("auth.access_key", "AUTH_ACCESS_KEY")
	viper.BindEnv("auth.refesh_key", "AUTH_REFESH_KEY")

	// Thực hiện unmarshal từ cấu hình
	if err := viper.Unmarshal(&cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}
