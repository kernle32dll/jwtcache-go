package jwt

import (
	"github.com/sirupsen/logrus"

	"errors"
	"sync"
	"time"
)

// CacheMap is a mapped implementation of Cache, which allows storing
// JWTs by a key (for example a tenant UUID). As a bonus, the map is
// concurrency safe.
type CacheMap struct {
	jwtMap map[string]*Cache
	lock   *sync.RWMutex

	name      string
	logger    *logrus.Logger
	headroom  time.Duration
	tokenFunc func(key string) (string, error)
}

// NewCacheMap returns a new mapped JWT cache.
func NewCacheMap(opts ...MapOption) *CacheMap {
	//default
	mapConfig := &mapConfig{
		name:     "",
		headroom: time.Second,
		logger:   logrus.StandardLogger(),
		tokenFunc: func(key string) (s string, e error) {
			return "", errors.New("not implemented")
		},
	}

	//apply opts
	for _, opt := range opts {
		opt(mapConfig)
	}

	return &CacheMap{
		jwtMap: map[string]*Cache{},
		lock:   &sync.RWMutex{},

		name:      mapConfig.name,
		logger:    mapConfig.logger,
		headroom:  mapConfig.headroom,
		tokenFunc: mapConfig.tokenFunc,
	}
}

type mapConfig struct {
	name      string
	logger    *logrus.Logger
	headroom  time.Duration
	tokenFunc func(key string) (string, error)
}

// MapOption represents an option for the mapped cache.
type MapOption func(*mapConfig)

// MapName sets the name of the cache.
// The default is an empty string.
func MapName(name string) MapOption {
	return func(c *mapConfig) {
		c.name = name
	}
}

// MapLogger sets the logger to be used.
// The default is the logrus default logger.
func MapLogger(logger *logrus.Logger) MapOption {
	return func(c *mapConfig) {
		c.logger = logger
	}
}

// Headroom sets the headroom on how much earlier the cached
// tokens should be considered expired.
// The default is 1 second.
func MapHeadroom(headroom time.Duration) MapOption {
	return func(c *mapConfig) {
		c.headroom = headroom
	}
}

// TokenFunction set the function which is called to retrieve a new
// JWT when required.
// The default always returns an error with "not implemented".
func MapTokenFunction(tokenFunc func(key string) (string, error)) MapOption {
	return func(c *mapConfig) {
		c.tokenFunc = tokenFunc
	}
}

// EnsureToken returns either the cached token if existing and still valid,
// or calls the internal token function to fetch a new token. If an error
// occurs in the latter case, it is passed trough.
func (cacheMap *CacheMap) EnsureToken(key string) (string, error) {
	return cacheMap.handleCacheExistence(key).EnsureToken()
}

// EnsureTokenSafe returns either the cached token if existing and still valid,
// or calls the internal token function to fetch a new token. If an error
// occurs in the latter case, it is passed trough.
// In contrast to EnsureToken, this function also validates the received JWT.
func (cacheMap *CacheMap) EnsureTokenSafe(key string, secret interface{}, method string) (string, error) {
	return cacheMap.handleCacheExistence(key).EnsureTokenSafe(secret, method)
}

func (cacheMap *CacheMap) handleCacheExistence(key string) *Cache {
	readLock := cacheMap.lock.RLocker()
	writeLock := cacheMap.lock

	readLock.Lock()

	cache, exists := cacheMap.jwtMap[key]
	if !exists {
		cache = NewCache(
			Name(cacheMap.name+" for "+key),
			Headroom(cacheMap.headroom),
			Logger(cacheMap.logger),
			TokenFunction(func() (string, error) {
				return cacheMap.tokenFunc(key)
			}),
		)

		// Trade read lock for write lock
		readLock.Unlock()

		writeLock.Lock()
		cacheMap.jwtMap[key] = cache
		writeLock.Unlock()
	} else {
		readLock.Unlock()
	}

	return cache
}
