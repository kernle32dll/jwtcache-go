package jwt

import (
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"

	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrNotImplemented is the default behavior for the cache, if the
	// token function is not supplied.
	ErrNotImplemented = errors.New("not implemented")
)

// LoggerContract defines the logging methods required by the cache.
// This allows to use different kinds of logging libraries.
type LoggerContract interface {
	Infof(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// Cache is a simple caching implementation to reuse JWTs till they expire.
type Cache struct {
	jwt      string
	validity time.Time

	name             string
	logger           LoggerContract
	headroom         time.Duration
	tokenFunc        func(ctx context.Context) (string, error)
	parseOptions     []jwt.ParseOption
	rejectUnparsable bool
}

// NewCache returns a new JWT cache.
func NewCache(opts ...Option) *Cache {
	//default
	config := &Config{
		Name:     "",
		Headroom: time.Second,
		Logger:   logrus.StandardLogger(),
		TokenFunc: func(ctx context.Context) (s string, e error) {
			return "", ErrNotImplemented
		},
		ParseOptions:     nil,
		RejectUnparsable: false,
	}

	//apply opts
	for _, opt := range opts {
		opt(config)
	}

	return &Cache{
		name:             config.Name,
		logger:           config.Logger,
		headroom:         config.Headroom,
		tokenFunc:        config.TokenFunc,
		parseOptions:     config.ParseOptions,
		rejectUnparsable: config.RejectUnparsable,
	}
}

// EnsureToken returns either the cached token if existing and still valid,
// or calls the internal token function to fetch a new token. If an error
// occurs in the latter case, it is passed trough.
func (jwtCache *Cache) EnsureToken(ctx context.Context) (string, error) {
	// Do we have a cached jwt, and its still valid?
	if jwtCache.jwt != "" && time.Now().Before(jwtCache.validity) {
		return jwtCache.jwt, nil
	}

	token, err := jwtCache.tokenFunc(ctx)
	if err != nil {
		return "", err
	}

	// Work with the parsed token - but don't fail, if we encounter an error
	parsedToken, err := jwt.ParseString(token, jwtCache.parseOptions...)
	if err != nil && jwtCache.rejectUnparsable {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	if err == nil {
		// Note: According to https://tools.ietf.org/html/rfc7519,
		// a "NumericDate" is defined as a UTC unix timestamp.
		iat := parsedToken.IssuedAt()
		exp := parsedToken.Expiration()

		if exp.IsZero() {
			jwtCache.jwt = ""
			jwtCache.logger.Infof("New %s received. Not 'exp' header set, so not caching", jwtCache.name)
		} else {
			// Cache the new token (and leave some headroom)
			jwtCache.jwt = token
			jwtCache.validity = exp.Add(-jwtCache.headroom)

			if !iat.IsZero() {
				jwtCache.logger.Debugf(
					"New %s received. Caching for %s",
					jwtCache.name,
					jwtCache.validity.Sub(iat.Add(-jwtCache.headroom)),
				)
			} else {
				jwtCache.logger.Debugf(
					"New %s received. Caching till %s",
					jwtCache.name,
					jwtCache.validity.Add(-jwtCache.headroom),
				)
			}
		}
	} else {
		jwtCache.logger.Debugf("Error while parsing %s: %s", jwtCache.name, err)
	}

	return token, nil
}
