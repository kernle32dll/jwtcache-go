package jwt

import (
	"context"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"time"
)

// Config bundles all available configuration
// properties for a Cache.
type Config struct {
	Name             string
	Logger           LoggerContract
	Headroom         time.Duration
	TokenFunc        func(ctx context.Context) (string, error)
	ParseOptions     []jwt.ParseOption
	RejectUnparsable bool
}

// Option represents an option for the cache.
type Option func(*Config)

// Name sets the name of the cache.
// The default is an empty string.
func Name(name string) Option {
	return func(c *Config) {
		c.Name = name
	}
}

// Logger sets the logger to be used.
// The default is the logrus default logger.
func Logger(logger LoggerContract) Option {
	return func(c *Config) {
		c.Logger = logger
	}
}

// Headroom sets the headroom on how much earlier the cached
// token should be considered expired.
// The default is 1 second.
func Headroom(headroom time.Duration) Option {
	return func(c *Config) {
		c.Headroom = headroom
	}
}

// TokenFunction set the function which is called to retrieve a new
// JWT when required.
// The default always returns an error with "not implemented".
func TokenFunction(tokenFunc func(ctx context.Context) (string, error)) Option {
	return func(c *Config) {
		c.TokenFunc = tokenFunc
	}
}

// ParseOptions set the parse options which are used to parse
// a JWT. This can be used to implement signature validation for example.
//
// The default empty.
func ParseOptions(parseOptions ...jwt.ParseOption) Option {
	return func(c *Config) {
		c.ParseOptions = parseOptions
	}
}

// RejectUnparsable sets if the cache should reject (and return
// the accompanying error) token which are not parsable.
// Note, unparsable can mean a failed signature check.
//
// The default is false.
func RejectUnparsable(rejectUnparsable bool) Option {
	return func(c *Config) {
		c.RejectUnparsable = rejectUnparsable
	}
}
