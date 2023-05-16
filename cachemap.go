package jwt

import (
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"

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
	logger           LoggerContract
	headroom         time.Duration
	tokenFunc        func(ctx context.Context, key string) (string, error)
	parseOptions     []jwt.ParseOption
	rejectUnparsable bool
}

// NewCacheMap returns a new mapped JWT cache.
func NewCacheMap(opts ...MapOption) *CacheMap {
	//default
	mapConfig := &MapConfig{
		Name:     "",
		Headroom: time.Second,
		Logger:   logrus.StandardLogger(),
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

	return &CacheMap{
		jwtMap: map[string]*Cache{},
		lock:   &sync.RWMutex{},

		name:             mapConfig.Name,
		logger:           mapConfig.Logger,
		headroom:         mapConfig.Headroom,
		tokenFunc:        mapConfig.TokenFunc,
		parseOptions:     mapConfig.ParseOptions,
		rejectUnparsable: mapConfig.RejectUnparsable,
	}
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
			Logger(cacheMap.logger),
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
