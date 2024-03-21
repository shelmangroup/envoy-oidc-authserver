package store

import (
	"log/slog"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	gocache_store "github.com/eko/gocache/store/go_cache/v4"
	redis_store "github.com/eko/gocache/store/redis/v4"
	gocache "github.com/patrickmn/go-cache"
	redis "github.com/redis/go-redis/v9"
)

type Store struct {
	*cache.Cache[any]
}

func NewStore(redisAddrs []string, expiration time.Duration) *Store {
	if redisAddrs == nil {
		gocacheClient := gocache.New(expiration, 10*time.Minute)
		gocacheStore := gocache_store.NewGoCache(gocacheClient)

		return &Store{
			cache.New[any](gocacheStore),
		}
	}

	slog.Info("Using Redis Sentinel cache", slog.Any("addrs", redisAddrs))
	redisClient := redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    "mymaster",
		SentinelAddrs: redisAddrs,
	})
	redisStore := redis_store.NewRedis(redisClient, store.WithExpiration(expiration))
	return &Store{
		cache.New[any](redisStore),
	}
}
