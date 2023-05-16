package jwt

import (
	"context"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"time"
)

// MapConfig bundles all available configuration
// properties for a CacheMap.
type MapConfig struct {
	Name             string
	Logger           LoggerContract
	Headroom         time.Duration
	TokenFunc        func(ctx context.Context, key string) (string, error)
	ParseOptions     []jwt.ParseOption
	RejectUnparsable bool
}

// MapOption represents an option for the mapped cache.
type MapOption func(*MapConfig)

// MapName sets the name of the cache.
// The default is an empty string.
func MapName(name string) MapOption {
	return func(c *MapConfig) {
		c.Name = name
	}
}

// MapLogger sets the logger to be used.
// The default is the logrus default logger.
func MapLogger(logger LoggerContract) MapOption {
	return func(c *MapConfig) {
		c.Logger = logger
	}
}

// MapHeadroom sets the headroom on how much earlier the cached
// tokens should be considered expired.
// The default is 1 second.
func MapHeadroom(headroom time.Duration) MapOption {
	return func(c *MapConfig) {
		c.Headroom = headroom
	}
}

// MapTokenFunction set the function which is called to retrieve a new
// JWT when required.
// The default always returns an error with "not implemented".
func MapTokenFunction(tokenFunc func(ctx context.Context, key string) (string, error)) MapOption {
	return func(c *MapConfig) {
		c.TokenFunc = tokenFunc
	}
}

// MapParseOptions set the parse options which are used to parse
// a JWT. This can be used to implement signature validation for example.
//
// The default empty.
func MapParseOptions(parseOptions ...jwt.ParseOption) MapOption {
	return func(c *MapConfig) {
		c.ParseOptions = parseOptions
	}
}

// MapRejectUnparsable sets if the cache should reject (and return
// the accompanying error) token which are not parsable.
// Note, unparsable can mean a failed signature check.
//
// The default is false.
func MapRejectUnparsable(rejectUnparsable bool) MapOption {
	return func(c *MapConfig) {
		c.RejectUnparsable = rejectUnparsable
	}
}
