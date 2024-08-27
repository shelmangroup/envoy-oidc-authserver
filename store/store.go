package store

import (
	"log/slog"
	"net/url"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	gocache_store "github.com/eko/gocache/store/go_cache/v4"
	redis_store "github.com/eko/gocache/store/redis/v4"
	gocache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/extra/redisotel/v9"
)

type Store struct {
	*cache.Cache[any]
}

func NewStore(url *url.URL, expiration time.Duration) *Store {
	if url.String() == "" {
		slog.Info("Using in memory cache")
		gocacheClient := gocache.New(expiration, 10*time.Minute)
		gocacheStore := gocache_store.NewGoCache(gocacheClient)

		return &Store{
			cache.New[any](gocacheStore),
		}
	}

	redisClient, err := GetRedisClient(url)
	if err != nil {
		slog.Error("Failed to connect to Redis", slog.String("err", err.Error()))
		panic(err)
	}
	if err := redisotel.InstrumentTracing(redisClient); err != nil {
		panic(err)
	}

	slog.Info("Using Redis cache", slog.String("url", url.String()))
	redisStore := redis_store.NewRedis(redisClient, store.WithExpiration(expiration))
	return &Store{
		cache.New[any](redisStore),
	}
}
