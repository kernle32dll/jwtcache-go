package jwt

import (
	"context"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"testing"
	"time"
)

// testLogger pipes the logging output to the test logger.
type testLogger struct {
	t *testing.T
}

func (logger testLogger) Infof(format string, args ...interface{}) {
	logger.t.Logf(format, args...)
}

func (logger testLogger) Debugf(format string, args ...interface{}) {
	logger.t.Logf(format, args...)
}

func getJwt(claims jwt.MapClaims) (string, error) {
	c := claims

	// Ensure new token on every invocation - iat and exp are only second-precise,
	// and thus don't warrant a new token without annoying sleep statements in tests.
	c["breaker"] = time.Now()

	return jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString([]byte("supersecretpassphrase"))
}

func getTokenFunction() func(ctx context.Context) (string, error) {
	now := time.Now()
	iat := now.Add(-time.Hour)
	exp := now.Add(time.Hour)

	return func(ctx context.Context) (string, error) {
		return getJwt(jwt.MapClaims{
			"iat": iat.Unix(),
			"exp": exp.Unix(),
		})
	}
}

func getTokenFunctionWithoutIat() func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		return getJwt(jwt.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
		})
	}
}

func getExpiredTokenFunction() func(ctx context.Context) (string, error) {
	now := time.Now()

	return func(ctx context.Context) (string, error) {
		return getJwt(jwt.MapClaims{
			"iat": now.Add(-time.Hour).Unix(),
			"exp": now.Add(-time.Hour).Unix(),
		})
	}
}

func getTokenFunctionWithoutExp() func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		return getJwt(jwt.MapClaims{
			"iat": time.Now().Add(-time.Hour).Unix(),
		})
	}
}

// Tests that a new cache uses the correct defaults
func Test_Cache_Defaults(t *testing.T) {
	// when
	cache := NewCache()

	// then
	if cache.name != "" {
		t.Error("default name not correctly applied")
	}

	if cache.logger != logrus.StandardLogger() {
		t.Error("default logger not correctly applied")
	}

	if cache.headroom != time.Second {
		t.Error("default headroom not correctly applied")
	}

	if _, err := cache.tokenFunc(context.Background()); err != ErrNotImplemented {
		t.Error("default token function not correctly applied")
	}
}

// Tests that EnsureToken returns the exact error, if any occurred
// while retrieving a new token.
func Test_Cache_EnsureToken_TokenError(t *testing.T) {
	// given
	expectedErr := errors.New("expected error")
	cache := NewCache(
		Logger(&testLogger{t}),
		TokenFunction(func(ctx context.Context) (s string, e error) {
			return "", expectedErr
		}),
	)

	// when
	token, err := cache.EnsureToken(context.Background())

	// then
	if err != expectedErr {
		t.Errorf("unexpected error while token function invocation: %s", err)
	}

	if token != "" {
		t.Errorf("expected empty token, but received: %s", token)
	}
}

// Tests that EnsureToken correctly caches the token, and does not
// call the token function multiple times.
func Test_Cache_EnsureToken_Cache(t *testing.T) {
	// given
	cache := NewCache(
		Logger(&testLogger{t}),
		TokenFunction(getTokenFunction()),
	)

	// when
	firstToken, firstErr := cache.EnsureToken(context.Background())
	secondToken, secondErr := cache.EnsureToken(context.Background())

	// then
	if firstErr != nil {
		t.Errorf("error while first token function invocation: %s", firstErr)
	}

	if secondErr != nil {
		t.Errorf("error while second token function invocation: %s", secondErr)
	}

	if firstToken != secondToken {
		t.Errorf("token was not cached")
	}
}

// Tests that EnsureToken correctly invalidates the cache, if the previous
// cached token expires
func Test_Cache_EnsureToken_Cache_Invalidation(t *testing.T) {
	// given
	cache := NewCache(
		Logger(&testLogger{t}),
		TokenFunction(getExpiredTokenFunction()),
	)

	// when
	firstToken, firstErr := cache.EnsureToken(context.Background())
	secondToken, secondErr := cache.EnsureToken(context.Background())

	// then
	if firstErr != nil {
		t.Errorf("error while first token function invocation: %s", firstErr)
	}

	if secondErr != nil {
		t.Errorf("error while second token function invocation: %s", secondErr)
	}

	if firstToken == secondToken {
		t.Errorf("token was cached, but was not supposed to")
	}
}

// Tests that EnsureToken does not cache the token, if the
// token provides not exp claim.
func Test_Cache_EnsureToken_NoExp(t *testing.T) {
	// given
	cache := NewCache(
		Logger(&testLogger{t}),
		TokenFunction(getTokenFunctionWithoutExp()),
	)

	// when
	firstToken, firstErr := cache.EnsureToken(context.Background())
	secondToken, secondErr := cache.EnsureToken(context.Background())

	// then
	if firstErr != nil {
		t.Errorf("error while first token function invocation: %s", firstErr)
	}

	if secondErr != nil {
		t.Errorf("error while second token function invocation: %s", secondErr)
	}

	if firstToken == secondToken {
		t.Errorf("token was cached, but was not supposed to")
	}
}

// Tests that EnsureToken correctly caches the token, and does not
// call the token function multiple times - even if the iat claim is missing.
func Test_Cache_EnsureToken_NoIat(t *testing.T) {
	// given
	cache := NewCache(
		Logger(&testLogger{t}),
		TokenFunction(getTokenFunctionWithoutIat()),
	)

	// when
	firstToken, firstErr := cache.EnsureToken(context.Background())
	secondToken, secondErr := cache.EnsureToken(context.Background())

	// then
	if firstErr != nil {
		t.Errorf("error while first token function invocation: %s", firstErr)
	}

	if secondErr != nil {
		t.Errorf("error while second token function invocation: %s", secondErr)
	}

	if firstToken != secondToken {
		t.Errorf("token was not cached")
	}
}

// Tests that EnsureToken does return the received token, even
// if it can't be parsed for caching usage.
func Test_Cache_EnsureToken_BrokenParser(t *testing.T) {
	// given
	counter := 0
	cache := NewCache(
		Logger(&testLogger{t}),
		TokenFunction(func(ctx context.Context) (s string, e error) {
			counter++
			return fmt.Sprintf("not-a-valid-token-%d", counter), nil
		}),
	)

	// when
	firstToken, firstErr := cache.EnsureToken(context.Background())
	secondToken, secondErr := cache.EnsureToken(context.Background())

	// then
	if firstErr != nil {
		t.Errorf("error while first token function invocation: %s", firstErr)
	}

	if secondErr != nil {
		t.Errorf("error while second token function invocation: %s", secondErr)
	}

	if firstToken == secondToken {
		t.Errorf("token was cached, but was not supposed to")
	}
}
