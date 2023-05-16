![test](https://github.com/kernle32dll/jwtcache-go/workflows/test/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/kernle32dll/jwtcache-go.svg)](https://pkg.go.dev/github.com/kernle32dll/jwtcache-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/kernle32dll/jwtcache-go)](https://goreportcard.com/report/github.com/kernle32dll/jwtcache-go)
[![codecov](https://codecov.io/gh/kernle32dll/jwtcache-go/branch/master/graph/badge.svg)](https://codecov.io/gh/kernle32dll/jwtcache-go)

# jwtcache-go

jwtcache-go is a small wrapper lib for caching JWTs.

The initial purpose for developing this lib was caching tokens that were issued for service2service communication.

An exemplary use case for this are
[Keycloak service accounts](https://www.keycloak.org/docs/latest/server_admin/index.html#_service_accounts).

Download:

```
go get github.com/kernle32dll/jwtcache-go
```

Detailed documentation can be found on [pkg.go.dev](https://pkg.go.dev/github.com/kernle32dll/jwtcache-go).

## Basic usage

**TL;DR**:

```go
package main

import (
	"github.com/kernle32dll/jwtcache-go"

	"context"
	"log"
)

func main() {
	cache := jwt.NewCache(
		jwt.Name("my cache"),
		jwt.TokenFunction(func(ctx context.Context) (string, error) {
			// ... actually acquire the token, and return it here
			return "someToken", nil
		}),
	)

	token, err := cache.EnsureToken(context.Background())
	if err != nil {
		// oh no...
	}

	log.Printf("got token: %s", token)
}
```

First, you have to instantiate a `jwt.Cache`. This is done via `jwt.NewCache` (which takes option style parameters).

The most important option parameter being the `jwt.TokenFunction`, which provides a token to the cache if required
(either no token is cached yet, or the existing token is expired). Look at
[pkg.go.dev](https://pkg.go.dev/github.com/kernle32dll/jwtcache-go) for other parameters.

With the cache instantiated, you can call the `EnsureToken` function to start transparently using the cache. Internally,
the cache will then use the `jwt.TokenFunction` to fetch a new token, and cache it afterwards for the validity time
provided by the token. Subsequent calls to `EnsureToken` will then return this cached token, till it expires.

```go
token, err := jwt.EnsureToken(context.Background())
```

**Implementation detail**: The validity check is done via the `exp` claim of the JWT. If it is not set, the token is
never cached. However, the token is still passed trough (and a warning is logged).

## JWT parser customization

Per default, jwtcache-go ignores JWTs it cannot parse, **but** still returns them from the token function. However, it
is possible to change this via the `jwt.RejectUnparsable(true)` option.

To make the most of this, you can also adjust the [underlying JWT parser](https://github.com/lestrrat-go/jwx), with
the `jwt.ParseOptions(...)` function. For example, you can easily enable signature verification like so:

```go
package main

import (
	"github.com/kernle32dll/jwtcache-go"
	"github.com/lestrrat-go/jwx/v2/jwa"
	jwtParser "github.com/lestrrat-go/jwx/v2/jwt"

	"context"
)

func main() {

	cache := jwt.NewCache(
		jwt.Name("signed cache"),
		jwt.TokenFunction(func(ctx context.Context) (string, error) {
			// ... actually acquire the token, and return it here
			return "someToken", nil
		}),
		// !! HMAC is shown for simplicity - use RSA, ECDSA or EdDSA instead !!
		jwt.ParseOptions(jwtParser.WithKey(jwa.HS256, []byte("supersecretpassphrase"))),
		jwt.RejectUnparsable(true), // Propagate parsing errors, instead of swallowing them
	)

	_, err := cache.EnsureToken(context.Background())
	if err != nil {
		// this will always happen, as "someToken" is not actually a valid HMAC signed JWT!
	}
}
```

## Advanced usage

In addition to the `jwt.Cache`, this lib has an additional trick up its sleeve in the form of `jwt.CacheMap`.

A `jwt.CacheMap` behaves identically to a `jwt.Cache`, with the difference that - as the name suggest - the cache is
actually a map compromised of several caches.

```go
package main

import (
	"github.com/kernle32dll/jwtcache-go"

	"context"
	"log"
)

func main() {
	tenantCache := jwt.NewCacheMap(
		jwt.MapName("my cache map"),
		jwt.MapTokenFunction(func(ctx context.Context, tenantUUID string) (string, error) {
			// ... actually acquire the token, and return it here
			return "some-token", nil
		}),
	)

	token, err := tenantCache.EnsureToken(context.Background(), "d1851563-c529-42d9-994b-6b996ec4b605")
	if err != nil {
		// oh no...
	}

	log.Printf("got token for tenant: %s", token)
}
```

The use-case `jwt.CacheMap` was implemented for was multi-tenant applications, which need to independently cache JWTs
per tenant (a good cache key might be the UUID of a tenant, for example).

**Implementation detail**: The underlying map is concurrency-safe, and lazily initialized.

## Compatibility

jwt-cache-go is automatically tested against Go `1.20`, `1.19` and `1.18`.
