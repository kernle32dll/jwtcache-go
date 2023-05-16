package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	jwt "github.com/kernle32dll/jwtcache-go"
	"github.com/lestrrat-go/jwx/v2/jwa"
	jwtx "github.com/lestrrat-go/jwx/v2/jwt"
	"testing"
	"time"
)

func getJwt(claims map[string]interface{}) (string, error) {
	token := jwtx.New()

	// Ensure new token on every invocation - iat and exp are only second-precise,
	// and thus don't warrant a new token without annoying sleep statements in tests.
	randomKey := make([]byte, 128)
	if _, err := rand.Read(randomKey); err != nil {
		return "", err
	}

	if err := token.Set("breaker", randomKey); err != nil {
		return "", err
	}

	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			return "", err
		}
	}

	signedT, err := jwtx.Sign(token, jwtx.WithKey(jwa.HS512, []byte("supersecretpassphrase")))
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
			jwtx.IssuedAtKey:   iat.UTC(),
			jwtx.ExpirationKey: exp.UTC(),
		})
	}
}

func getTokenFunctionWithoutIat() func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		return getJwt(map[string]interface{}{
			jwtx.ExpirationKey: time.Now().Add(time.Hour).UTC(),
		})
	}
}

func getExpiredTokenFunction() func(ctx context.Context) (string, error) {
	now := time.Now()

	return func(ctx context.Context) (string, error) {
		return getJwt(map[string]interface{}{
			jwtx.IssuedAtKey:   now.Add(-time.Hour).UTC(),
			jwtx.ExpirationKey: now.Add(-time.Hour).UTC(),
		})
	}
}

func getTokenFunctionWithoutExp() func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		return getJwt(map[string]interface{}{
			jwtx.IssuedAtKey: time.Now().Add(-time.Hour).UTC(),
		})
	}
}

// Tests that EnsureToken returns the exact error, if any occurred
// while retrieving a new logger.
func Test_Cache_EnsureToken_LoggerError(t *testing.T) {
	// given
	expectedErr := errors.New("expected error")
	cache := jwt.NewCache(
		jwt.Name(t.Name()),
		jwt.LoggerFunction(func(ctx context.Context) (jwt.LoggerContract, error) {
			return nil, expectedErr
		}),
	)

	// when
	token, err := cache.EnsureToken(context.Background())

	// then
	if err != expectedErr {
		t.Errorf("unexpected error while logger function invocation: %s", err)
	}

	if token != "" {
		t.Errorf("expected empty token, but received: %s", token)
	}
}

// Tests that EnsureToken returns an ErrNotImplemented error, if no
// token function has been defined.
func Test_Cache_EnsureToken_NotImplementedError(t *testing.T) {
	// given
	expectedErr := jwt.ErrNotImplemented
	cache := jwt.NewCache(
		jwt.Name(t.Name()),
	)

	// when
	token, err := cache.EnsureToken(context.Background())

	// then
	if err != expectedErr {
		t.Errorf("unexpected error while logger function invocation: %s", err)
	}

	if token != "" {
		t.Errorf("expected empty token, but received: %s", token)
	}
}

// Tests that EnsureToken returns the exact error, if any occurred
// while retrieving a new token.
func Test_Cache_EnsureToken_TokenError(t *testing.T) {
	// given
	expectedErr := errors.New("expected error")
	cache := jwt.NewCache(
		jwt.Name(t.Name()),
		jwt.TokenFunction(func(ctx context.Context) (s string, e error) {
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
	cache := jwt.NewCache(
		jwt.Name(t.Name()),
		jwt.TokenFunction(getTokenFunction()),
		jwt.ParseOptions(jwtx.WithVerify(false)),
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
	cache := jwt.NewCache(
		jwt.Name(t.Name()),
		jwt.TokenFunction(getExpiredTokenFunction()),
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
	cache := jwt.NewCache(
		jwt.Name(t.Name()),
		jwt.TokenFunction(getTokenFunctionWithoutExp()),
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
	cache := jwt.NewCache(
		jwt.Name(t.Name()),
		jwt.TokenFunction(getTokenFunctionWithoutIat()),
		jwt.ParseOptions(jwtx.WithVerify(false)),
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
	cache := jwt.NewCache(
		jwt.Name(t.Name()),
		jwt.TokenFunction(func(ctx context.Context) (s string, e error) {
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

// Tests that EnsureToken does return a parsing error, if RejectUnparsable
// is enabled, and the token cannot be parsed (e.g. due to a signing error)
func Test_Cache_EnsureToken_BrokenParser_Reject(t *testing.T) {
	// given
	counter := 0
	cache := jwt.NewCache(
		jwt.Name(t.Name()),
		jwt.TokenFunction(func(ctx context.Context) (s string, e error) {
			counter++
			return fmt.Sprintf("not-a-valid-token-%d", counter), nil
		}),
		jwt.RejectUnparsable(true),
	)

	// when
	token, firstErr := cache.EnsureToken(context.Background())

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
func Test_Cache_EnsureToken_Signed_JWT(t *testing.T) {
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.FailNow()
	}
	ecdsaPublicKey := ecdsaPrivateKey.Public()

	// given
	cache := jwt.NewCache(
		jwt.Name(t.Name()),
		jwt.TokenFunction(func(ctx context.Context) (s string, e error) {
			signedToken, err := jwtx.Sign(jwtx.New(), jwtx.WithKey(jwa.ES512, ecdsaPrivateKey))
			if err != nil {
				return "", err
			}

			return string(signedToken), nil
		}),
		jwt.ParseOptions(jwtx.WithKey(jwa.ES512, ecdsaPublicKey)),
		// Set, so that verification fails if we provide a wrong JWT in the
		jwt.RejectUnparsable(true),
	)

	// when
	token, err := cache.EnsureToken(context.Background())

	// then
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if token == "" {
		t.Error("expected token, but got none")
	}
}
