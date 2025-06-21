package redis

import (
	config "bulbasaur/pkg/config"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	re "github.com/redis/go-redis/v9"
)

type Redis interface {
	Set(ctx context.Context, key, value string, expireTime time.Duration) (bool, error)
	Get(ctx context.Context, key string) (string, error)
	Check(ctx context.Context, key, value string) bool
	Delete(ctx context.Context, key string) error

	SetJSON(ctx context.Context, key string, value interface{}, expireTime time.Duration) error
	GetJSON(ctx context.Context, key string, result interface{}) error
	Exists(ctx context.Context, key string) (bool, error)
	Keys(ctx context.Context, pattern string) ([]string, error)
}

type redis struct {
	redis     *re.Client
	namespace string
}

func New(enable bool, cfg *config.Config) Redis {
	if !enable {
		return Noop()
	}

	return &redis{
		redis: re.NewClient(&re.Options{
			Addr:     cfg.Redis.Address,
			Password: cfg.Redis.Password,
		}),
		namespace: cfg.Redis.Namespace, // Assuming namespace is part of the config
	}
}

func (r *redis) withNamespace(key string) string {
	return fmt.Sprintf("%s:%s", r.namespace, key)
}

func (r *redis) Set(ctx context.Context, key, value string, expireTime time.Duration) (bool, error) {
	namespacedKey := r.withNamespace(key)
	return r.redis.Set(ctx, namespacedKey, value, expireTime).Err() == nil, nil
}

func (r *redis) Get(ctx context.Context, key string) (string, error) {
	namespacedKey := r.withNamespace(key)
	val, err := r.redis.Get(ctx, namespacedKey).Result()
	if err == re.Nil {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return val, nil
}

func (r *redis) Check(ctx context.Context, key, value string) bool {
	namespacedKey := r.withNamespace(key)
	return r.redis.Get(ctx, namespacedKey).Val() == value
}

func (r *redis) Delete(ctx context.Context, key string) error {
	if strings.HasPrefix(key, r.namespace+":") {
		return r.redis.Del(ctx, key).Err()
	}

	namespacedKey := r.withNamespace(key)
	return r.redis.Del(ctx, namespacedKey).Err()
}

func (r *redis) SetJSON(ctx context.Context, key string, value interface{}, expire time.Duration) error {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return err
	}
	namespacedKey := r.withNamespace(key)
	err = r.redis.Set(ctx, namespacedKey, string(jsonData), expire).Err()
	return err
}

func (r *redis) GetJSON(ctx context.Context, key string, result interface{}) error {
	if strings.HasPrefix(key, r.namespace+":") {
		data, err := r.redis.Get(ctx, key).Result()
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(data), result)
	}

	namespacedKey := r.withNamespace(key)
	data, err := r.redis.Get(ctx, namespacedKey).Result()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), result)
}

func (r *redis) Exists(ctx context.Context, key string) (bool, error) {
	namespacedKey := r.withNamespace(key)
	count, err := r.redis.Exists(ctx, namespacedKey).Result()
	return count > 0, err
}

func (r *redis) Keys(ctx context.Context, pattern string) ([]string, error) {
	return r.redis.Keys(ctx, fmt.Sprintf("%s:%s", r.namespace, pattern)).Result()
}
