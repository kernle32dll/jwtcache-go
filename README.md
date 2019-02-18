# jwtcache-go

jwtcache-go is a small wrapper lib for caching JWTs.

The initial purpose for developing this wrapper was caching tokens that were issued for service2service communication.

An exemplary use case for this are [Keycloak service accounts](https://www.keycloak.org/docs/4.8/server_admin/index.html#_service_accounts).

Download:

```
go get github.com/kernle32dll/jwtcache-go
```

Detailed documentation can be found on [GoDoc](https://godoc.org/github.com/kernle32dll/jwtcache-go).

### Usage

First, you have to instantiate a `jwt.Cache`. This is done via `jwt.NewCache` (which takes option style parameters).

```go
cache := jwt.NewCache(
    jwt.TokenFunction(func(ctx context.Context) (string, error) {
    	// ... actually acquire the token, and return it here
        return someToken, nil
    }),
)
```

The most important option parameter being the `jwt.TokenFunction`, which provides a token to the cache if required
(either no token is cached yet, or the existing token is expired). Look at [GoDoc](https://godoc.org/github.com/kernle32dll/jwtcache-go)
for other parameters.

With the cache instantiated, you can call the `EnsureToken` function to start transparently using the cache. Internally,
the cache will then use the `jwt.TokenFunction` to fetch a new token, and cache it afterwards for the validity time
provided by the token. Subsequent calls to `EnsureToken` will then return this cached token, till it expires.

```go
token, err := jwt.EnsureToken(context.Background())
```

**Implementation detail**: The validity check is done via the `exp` claim of the JWT. If it is not set, the token is never
cached. However, the token is still passed trough (and a warning is logged).

### Further usage

In addition to the `jwt.Cache`, this lib as an additional trick up its sleeve in the form of the `jwt.CacheMap`.

A `jwt.CacheMap` behaves identically to a `jwt.Cache`, with the difference that - as the name suggest - the cache
is actually a map compromised of several caches.

```go
tenantCache: jwt.NewCacheMap(
    jwtCache.MapTokenFunction(func(ctx context.Context, tenantUUID string) (string, error) {
    	// ... actually acquire the token, and return it here
        return token, err
    }),
)

tenantCache.EnsureToken(context.Background(), "d1851563-c529-42d9-994b-6b996ec4b605")
```

The use-case `jwt.CacheMap` was implemented for was multi-tenant applications, which need to independently cache
JWTs per tenant (a good cache key might be the UUID of a tenant, for example).

**Implementation detail**: The underlying map is concurrency-safe, and lazily initialized.