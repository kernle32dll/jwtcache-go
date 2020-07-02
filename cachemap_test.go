package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"

	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"
	"time"
)

func getMapTokenFunction() func(ctx context.Context, key string) (string, error) {
	now := time.Now()
	iat := now.Add(-time.Hour)
	exp := now.Add(time.Hour)

	return func(ctx context.Context, key string) (string, error) {
		return getJwt(jwt.MapClaims{
			"iat": iat.Unix(),
			"exp": exp.Unix(),
		})
	}
}

func getMapTokenFunctionWithoutIat() func(ctx context.Context, key string) (string, error) {
	return func(ctx context.Context, key string) (string, error) {
		return getJwt(jwt.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
		})
	}
}

func getMapExpiredTokenFunction() func(ctx context.Context, key string) (string, error) {
	now := time.Now()

	return func(ctx context.Context, key string) (string, error) {
		return getJwt(jwt.MapClaims{
			"iat": now.Add(-time.Hour).Unix(),
			"exp": now.Add(-time.Hour).Unix(),
		})
	}
}

func getMapTokenFunctionWithoutExp() func(ctx context.Context, key string) (string, error) {
	return func(ctx context.Context, key string) (string, error) {
		return getJwt(jwt.MapClaims{
			"iat": time.Now().Add(-time.Hour).Unix(),
		})
	}
}

// Tests that a new cache uses the correct defaults
func Test_CacheMap_Defaults(t *testing.T) {
	// when
	cache := NewCacheMap()

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

	if _, err := cache.tokenFunc(context.Background(), "somekey"); err != ErrNotImplemented {
		t.Error("default token function not correctly applied")
	}
}

// Tests that EnsureToken returns the exact error, if any occurred
// while retrieving a new token.
func Test_CacheMap_EnsureToken_TokenError(t *testing.T) {
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	expectedErr := errors.New("expected error")
	cache := NewCacheMap(
		MapLogger(logger),
		MapTokenFunction(func(ctx context.Context, key string) (s string, e error) {
			return "", expectedErr
		}),
	)

	// when
	token, err := cache.EnsureToken(context.Background(), "some-key")

	// then
	if err != expectedErr {
		t.Errorf("unexpected error while token function invocation: %s", err)
	}

	if token != "" {
		t.Errorf("expected empty token, but received: %s", token)
	}
}

// Tests that EnsureToken correctly caches the token, and does not
// call the token function multiple times. However, a different key
// does warrant a new token again.
func Test_CacheMap_EnsureToken_Cache(t *testing.T) {
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	cache := NewCacheMap(
		MapLogger(logger),
		MapTokenFunction(getMapTokenFunction()),
	)

	// when
	firstToken, firstErr := cache.EnsureToken(context.Background(), "some-key")
	secondToken, secondErr := cache.EnsureToken(context.Background(), "some-key")
	thirdToken, thirdErr := cache.EnsureToken(context.Background(), "another-key")
	fourthToken, fourthErr := cache.EnsureToken(context.Background(), "another-key")

	// then
	if firstErr != nil {
		t.Errorf("error while first token function invocation: %s", firstErr)
	}

	if secondErr != nil {
		t.Errorf("error while second token function invocation: %s", secondErr)
	}

	if thirdErr != nil {
		t.Errorf("error while third token function invocation: %s", secondErr)
	}

	if fourthErr != nil {
		t.Errorf("error while fourth token function invocation: %s", secondErr)
	}

	if firstToken != secondToken {
		t.Errorf(`"some-key" token was not cached`)
	}

	if thirdToken != fourthToken {
		t.Errorf(`"another-key" token was not cached`)
	}

	if firstToken == thirdToken {
		t.Errorf("cached across keys")
	}
}

// Tests that EnsureToken correctly invalidates the cache, if the previous
// cached token expires
func Test_CacheMap_EnsureToken_Cache_Invalidation(t *testing.T) {
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	cache := NewCacheMap(
		MapLogger(logger),
		MapTokenFunction(getMapExpiredTokenFunction()),
	)

	// when
	firstToken, firstErr := cache.EnsureToken(context.Background(), "some-key")
	secondToken, secondErr := cache.EnsureToken(context.Background(), "some-key")

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
func Test_CacheMap_EnsureToken_NoExp(t *testing.T) {
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	cache := NewCacheMap(
		MapLogger(logger),
		MapTokenFunction(getMapTokenFunctionWithoutExp()),
	)

	// when
	firstToken, firstErr := cache.EnsureToken(context.Background(), "some-key")
	secondToken, secondErr := cache.EnsureToken(context.Background(), "some-key")

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
func Test_CacheMap_EnsureToken_NoIat(t *testing.T) {
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	cache := NewCacheMap(
		MapLogger(logger),
		MapTokenFunction(getMapTokenFunctionWithoutIat()),
	)

	// when
	firstToken, firstErr := cache.EnsureToken(context.Background(), "some-key")
	secondToken, secondErr := cache.EnsureToken(context.Background(), "some-key")

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
func Test_CacheMap_EnsureToken_BrokenParser(t *testing.T) {
	logger := logrus.New()
	logger.Out = ioutil.Discard

	// given
	counter := 0
	cache := NewCacheMap(
		MapLogger(logger),
		MapTokenFunction(func(ctx context.Context, key string) (s string, e error) {
			counter++
			return fmt.Sprintf("not-a-valid-token-%d", counter), nil
		}),
	)

	// when
	firstToken, firstErr := cache.EnsureToken(context.Background(), "some-key")
	secondToken, secondErr := cache.EnsureToken(context.Background(), "some-key")

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