package redis

import (
	"bulbasaur/package/config"
	"context"
	"fmt"
	"time"

	re "github.com/redis/go-redis/v9"
)

type Redis interface {
	Set(ctx context.Context, key, value string, expireTime time.Duration) (bool, error)
	Check(ctx context.Context, key, value string) bool
	Delete(ctx context.Context, key string) error
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
			Addr: cfg.Redis.Address,
		}),
		namespace: cfg.Redis.Namespace, // Assuming namespace is part of the config
	}
}

func (r *redis) withNamespace(key string) string {
	return fmt.Sprintf("%s:%s", r.namespace, key)
}

func (r *redis) Set(ctx context.Context, key, value string, expireTime time.Duration) (bool, error) {
	namespacedKey := r.withNamespace(key)
	return r.redis.SetNX(ctx, namespacedKey, value, expireTime).Result()
}

func (r *redis) Check(ctx context.Context, key, value string) bool {
	namespacedKey := r.withNamespace(key)
	return r.redis.Get(ctx, namespacedKey).Val() == value
}

func (r *redis) Delete(ctx context.Context, key string) error {
	namespacedKey := r.withNamespace(key)
	return r.redis.Del(ctx, namespacedKey).Err()
}