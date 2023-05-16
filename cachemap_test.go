package jwt_test

import (
	jwt "github.com/kernle32dll/jwtcache-go"
	"github.com/lestrrat-go/jwx/v2/jwa"
	jwtx "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/sirupsen/logrus"

	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"
)

func getMapTokenFunction() func(ctx context.Context, key string) (string, error) {
	now := time.Now()
	iat := now.Add(-time.Hour)
	exp := now.Add(time.Hour)

	return func(ctx context.Context, key string) (string, error) {
		return getJwt(map[string]interface{}{
			jwtx.IssuedAtKey:   iat.UTC(),
			jwtx.ExpirationKey: exp.UTC(),
		})
	}
}

func getMapTokenFunctionWithoutIat() func(ctx context.Context, key string) (string, error) {
	return func(ctx context.Context, key string) (string, error) {
		return getJwt(map[string]interface{}{
			jwtx.ExpirationKey: time.Now().Add(time.Hour).UTC(),
		})
	}
}

func getMapExpiredTokenFunction() func(ctx context.Context, key string) (string, error) {
	now := time.Now()

	return func(ctx context.Context, key string) (string, error) {
		return getJwt(map[string]interface{}{
			jwtx.IssuedAtKey:   now.Add(-time.Hour).UTC(),
			jwtx.ExpirationKey: now.Add(-time.Hour).UTC(),
		})
	}
}

func getMapTokenFunctionWithoutExp() func(ctx context.Context, key string) (string, error) {
	return func(ctx context.Context, key string) (string, error) {
		return getJwt(map[string]interface{}{
			jwtx.IssuedAtKey: time.Now().Add(-time.Hour).UTC(),
		})
	}
}

// Tests that EnsureToken returns the exact error, if any occurred
// while retrieving a new token.
func Test_CacheMap_EnsureToken_TokenError(t *testing.T) {
	logger := logrus.New()
	logger.Out = io.Discard

	// given
	expectedErr := errors.New("expected error")
	cache := jwt.NewCacheMap(
		jwt.MapName(t.Name()),
		jwt.MapLogger(logger),
		jwt.MapTokenFunction(func(ctx context.Context, key string) (s string, e error) {
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
	logger.Out = io.Discard

	// given
	cache := jwt.NewCacheMap(
		jwt.MapName(t.Name()),
		jwt.MapLogger(logger),
		jwt.MapTokenFunction(getMapTokenFunction()),
		jwt.MapParseOptions(jwtx.WithVerify(false)),
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
	logger.Out = io.Discard

	// given
	cache := jwt.NewCacheMap(
		jwt.MapName(t.Name()),
		jwt.MapLogger(logger),
		jwt.MapTokenFunction(getMapExpiredTokenFunction()),
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
	logger.Out = io.Discard

	// given
	cache := jwt.NewCacheMap(
		jwt.MapName(t.Name()),
		jwt.MapLogger(logger),
		jwt.MapTokenFunction(getMapTokenFunctionWithoutExp()),
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
	logger.Out = io.Discard

	// given
	cache := jwt.NewCacheMap(
		jwt.MapName(t.Name()),
		jwt.MapLogger(logger),
		jwt.MapTokenFunction(getMapTokenFunctionWithoutIat()),
		jwt.MapParseOptions(jwtx.WithVerify(false)),
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
	logger.Out = io.Discard

	// given
	counter := 0
	cache := jwt.NewCacheMap(
		jwt.MapName(t.Name()),
		jwt.MapLogger(logger),
		jwt.MapTokenFunction(func(ctx context.Context, key string) (s string, e error) {
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

// Tests that EnsureToken does return a parsing error, if RejectUnparsable
// is enabled, and the token cannot be parsed (e.g. due to a signing error)
func Test_CacheMap_EnsureToken_BrokenParser_Reject(t *testing.T) {
	logger := logrus.New()
	logger.Out = io.Discard

	// given
	counter := 0
	cache := jwt.NewCacheMap(
		jwt.MapName(t.Name()),
		jwt.MapLogger(logger),
		jwt.MapTokenFunction(func(ctx context.Context, key string) (s string, e error) {
			counter++
			return fmt.Sprintf("not-a-valid-token-%d", counter), nil
		}),
		jwt.MapRejectUnparsable(true),
	)

	// when
	token, firstErr := cache.EnsureToken(context.Background(), "some-key")

	// then
	if firstErr == nil {
		t.Error("expected error, but got none")
	}

	if token != "" {
		t.Errorf("received token %q, not expected none", token)
	}
}

// Tests that EnsureToken correctly verifies JWT signatures,
// if configured.
func Test_MapCache_EnsureToken_Signed_JWT(t *testing.T) {
	logger := logrus.New()
	logger.Out = io.Discard

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.FailNow()
	}
	ecdsaPublicKey := ecdsaPrivateKey.Public()

	// given
	cache := jwt.NewCacheMap(
		jwt.MapName(t.Name()),
		jwt.MapLogger(logger),
		jwt.MapTokenFunction(func(ctx context.Context, key string) (s string, e error) {
			signedToken, err := jwtx.Sign(jwtx.New(), jwtx.WithKey(jwa.ES512, ecdsaPrivateKey))
			if err != nil {
				return "", err
			}

			return string(signedToken), nil
		}),
		jwt.MapParseOptions(jwtx.WithKey(jwa.ES512, ecdsaPublicKey)),
		// Set, so that verification fails if we provide a wrong JWT in the
		jwt.MapRejectUnparsable(true),
	)

	// when
	token, err := cache.EnsureToken(context.Background(), "some-key")

	// then
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if token == "" {
		t.Error("expected token, but got none")
	}
}
