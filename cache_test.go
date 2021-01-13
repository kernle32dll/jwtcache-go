package jwt

import (
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"

	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"
	"time"
)

func getJwt(claims map[string]interface{}) (string, error) {
	token := jwt.New()

	// Ensure new token on every invocation - iat and exp are only second-precise,
	// and thus don't warrant a new token without annoying sleep statements in tests.
	if err := token.Set("breaker", time.Now()); err != nil {
		return "", err
	}

	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			return "", err
		}
	}

	signedT, err := jwt.Sign(token, jwa.HS512, []byte("supersecretpassphrase"))
	if err != nil {
		return "", err
	}

	return string(signedT), nil
}

func getTokenFunction() func(ctx context.Context) (string, error) {
	now := time.Now()
	iat := now.Add(-time.Hour)
	exp := now.Add(time.Hour)

	return func(ctx context.Context) (string, error) {
		return getJwt(map[string]interface{}{
			jwt.IssuedAtKey:   iat.UTC(),
			jwt.ExpirationKey: exp.UTC(),
		})
	}
}

func getTokenFunctionWithoutIat() func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		return getJwt(map[string]interface{}{
			jwt.ExpirationKey: time.Now().Add(time.Hour).UTC(),
		})
	}
}

func getExpiredTokenFunction() func(ctx context.Context) (string, error) {
	now := time.Now()

	return func(ctx context.Context) (string, error) {
		return getJwt(map[string]interface{}{
			jwt.IssuedAtKey:   now.Add(-time.Hour).UTC(),
			jwt.ExpirationKey: now.Add(-time.Hour).UTC(),
		})
	}
}

func getTokenFunctionWithoutExp() func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		return getJwt(map[string]interface{}{
			jwt.IssuedAtKey: time.Now().Add(-time.Hour).UTC(),
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
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	expectedErr := errors.New("expected error")
	cache := NewCache(
		Logger(logger),
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
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	cache := NewCache(
		Logger(logger),
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
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	cache := NewCache(
		Logger(logger),
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
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	cache := NewCache(
		Logger(logger),
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
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	cache := NewCache(
		Logger(logger),
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
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	counter := 0
	cache := NewCache(
		Logger(logger),
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
