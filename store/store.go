package store

import (
	"time"

	"github.com/allegro/bigcache"
	"github.com/eko/gocache/lib/v4/cache"
	bigcache_store "github.com/eko/gocache/store/bigcache/v4"
)

type Store struct {
	*cache.Cache[[]byte]
}

func NewStore() *Store {
	bigcacheClient, _ := bigcache.NewBigCache(bigcache.DefaultConfig(24 * time.Hour))
	bigcacheStore := bigcache_store.NewBigcache(bigcacheClient)
	// TODO: chain the cache with a redis cache
	c := cache.New[[]byte](bigcacheStore)
	return &Store{
		c,
	}
}
