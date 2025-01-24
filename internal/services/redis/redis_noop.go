package redis

import (
	"context"
	"time"
)

type noop struct {
	Redis
}

func Noop() Redis {
	return &noop{}
}

func (d *noop) Set(ctx context.Context, key string, expireTime time.Duration) (bool, error) {
	return false, nil
}
func (d *noop) Check(ctx context.Context, key string) bool {
	return false
}

func (d *noop) Delete(ctx context.Context, key string) error {
	return nil
}
