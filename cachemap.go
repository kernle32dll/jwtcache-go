package jwt

import (
	"github.com/lestrrat-go/jwx/v2/jwt"

	"context"
	"sync"
	"time"
)

// CacheMap is a mapped implementation of Cache, which allows storing
// JWTs by a key (for example a tenant UUID). As a bonus, the map is
// concurrency safe.
type CacheMap struct {
	jwtMap map[string]*Cache
	lock   *sync.RWMutex

	name             string
	loggerFunc       func(ctx context.Context, key string) (LoggerContract, error)
	headroom         time.Duration
	tokenFunc        func(ctx context.Context, key string) (string, error)
	parseOptions     []jwt.ParseOption
	rejectUnparsable bool
}

// NewCacheMapFromConfig returns a new mapped JWT cache.
func NewCacheMapFromConfig(mapConfig *MapConfig) *CacheMap {
	return &CacheMap{
		jwtMap: map[string]*Cache{},
		lock:   &sync.RWMutex{},

		name:             mapConfig.Name,
		loggerFunc:       mapConfig.LoggerFunc,
		headroom:         mapConfig.Headroom,
		tokenFunc:        mapConfig.TokenFunc,
		parseOptions:     mapConfig.ParseOptions,
		rejectUnparsable: mapConfig.RejectUnparsable,
	}
}

// NewCacheMap returns a new mapped JWT cache.
func NewCacheMap(opts ...MapOption) *CacheMap {
	//default
	mapConfig := &MapConfig{
		Name:     "",
		Headroom: time.Second,
		LoggerFunc: func(ctx context.Context, key string) (LoggerContract, error) {
			return &NoopLogger{}, nil
		},
		TokenFunc: func(ctx context.Context, key string) (s string, e error) {
			return "", ErrNotImplemented
		},
		ParseOptions:     nil,
		RejectUnparsable: false,
	}

	//apply opts
	for _, opt := range opts {
		opt(mapConfig)
	}

	return NewCacheMapFromConfig(mapConfig)
}

// EnsureToken returns either the cached token if existing and still valid,
// or calls the internal token function to fetch a new token. If an error
// occurs in the latter case, it is passed through.
func (cacheMap *CacheMap) EnsureToken(ctx context.Context, key string) (string, error) {
	readLock := cacheMap.lock.RLocker()
	writeLock := cacheMap.lock

	readLock.Lock()

	cache, exists := cacheMap.jwtMap[key]
	if !exists {
		// Trade read lock for write lock
		readLock.Unlock()
		writeLock.Lock()

		cacheMap.jwtMap[key] = NewCache(
			Name(cacheMap.name+" for "+key),
			Headroom(cacheMap.headroom),
			LoggerFunction(func(ctx context.Context) (LoggerContract, error) {
				return cacheMap.loggerFunc(ctx, key)
			}),
			TokenFunction(func(ctx context.Context) (string, error) {
				return cacheMap.tokenFunc(ctx, key)
			}),
			ParseOptions(cacheMap.parseOptions...),
			RejectUnparsable(cacheMap.rejectUnparsable),
		)

		cache = cacheMap.jwtMap[key]

		// Trade write lock for read lock
		writeLock.Unlock()
		readLock.Lock()
	}

	// Ensure that we unlock, even if the key function misbehaves
	defer readLock.Unlock()

	return cache.EnsureToken(ctx)
}
