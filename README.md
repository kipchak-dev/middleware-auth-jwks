# JWKS Middleware for Kipchak

This Middleware package provides OAuth 2.0 JWT Bearer Token Authentication support for Kipchak APIs using JWKS.

#### Composer Package

`kipchak/middleware-auth-jwks`

## How to use it?

Install it via composer: `composer require kipchak/middleware-auth-jwks`.

Then configure it in `config/kipchak.auth.jwks.php`; `vendor/bin/kipchak add auth-jwks` copies
[sample.config.php](sample.config.php) there.

## Configuration

| Key | Required | What it does |
|---|---|---|
| `jwksUri` | Yes | The JWKS endpoint of your identity provider. |
| `issuer` | Yes | The exact `iss` of the tokens you accept. For Keycloak: `https://<host>/realms/<realm>`. |
| `audience` | Yes | A non-empty list of the client IDs whose tokens this API accepts. |
| `token_type` | No | When set, the token's `typ` claim must equal it. Set `'Bearer'` for Keycloak. |
| `validate_scopes`, `scopes` | No | When `validate_scopes` is true, the token must carry **every** scope in `scopes`. |
| `key_set_ttl` | No | Seconds a fetched key set is trusted before it is fetched again; default 86400. SR-2026-013 requires 3600 or less, so that a key the identity provider withdraws stops being accepted within the hour. A value that is not a whole number of seconds, at least 1, fails at boot. |
| `enabled`, `ignore_options`, `ignore_paths` | No | Apply it globally; let preflight requests and the listed paths through. |

**Audience.** A token is accepted when one of the `audience` entries is in its `aud` claim (a string or a list) or
equals its `azp` claim. Keycloak puts the client a token was issued to in `azp`; the `aud` of an access token is
often only `account`. So for Keycloak, list the client IDs of the applications that call this API.

**Token type.** Keycloak signs ID tokens with the same keys as access tokens, and gives them the client in `aud`, so
the audience check alone accepts them. Its access tokens carry `typ: Bearer` and its ID tokens `typ: ID`, so
`'token_type' => 'Bearer'` refuses ID tokens. Leave it out only for identity providers that put no `typ` claim in
the token, such as Entra ID.

**Scopes** passed on a route, `new AuthJWKS($container, ['orders:read'])`, replace the configured ones, and are all
required too.

The middleware throws a `ConfigurationException` when it is built without `issuer`, `audience` or `jwksUri`, so a
service with an incomplete configuration fails at boot instead of accepting tokens for other clients.

## Responses and the key set

Refusals use the same statuses as kipchak/middleware-error, from kipchak/core's `ErrorStatus`, so an API gives one
name for each refusal however it arises. Every token that fails verification (signature, expiry, issuer, audience,
type) gets a 401 `UNAUTHENTICATED` with the message `Invalid token`; the reason is logged at `info`. A missing token
gets a 401 `UNAUTHENTICATED` with `No token found`. A valid token without a required scope gets a 403
`INSUFFICIENT_PRIVILEGES` with `Missing required scope(s)`: the caller is known but not allowed (RFC 6750, section 3.1).

The key set is cached for `key_set_ttl` seconds, a day by default. The lifetime is part of the cache key, so lowering it
takes effect on the next request rather than when the entry cached under the old lifetime expires. Only a valid key set is cached: when the fetch fails, or the document has no `keys`,
the request gets a 401, the error is logged, and the next request fetches again. A token whose `kid` the cached set
does not have causes one new fetch, at most once a minute, so a key rotated at the identity provider is picked up
straight away.

## Upgrading to 1.42

1.42 requires kipchak/core 3.18 and changes what a client receives, not the configuration:

1. **The status of a 401 is `UNAUTHENTICATED`**, not `UNAUTHORIZED`, as kipchak/middleware-error already writes it.
2. **A valid token without a required scope gets 403 `INSUFFICIENT_PRIVILEGES`**, not 401. A client that treats every
   401 as "sign in again" now shows a refusal for that case instead.
3. **`key_set_ttl`** is new and optional. Set it to 3600 or less to meet SR-2026-013.

## Upgrading to 1.41

1.41 fixes a security issue: earlier versions accepted any token the identity provider signed, for any of its
clients, including ID tokens. It changes three things, and an API keeps working only once its configuration has
the new keys:

1. **Add `issuer` and `audience`** to `config/kipchak.auth.jwks.php`, and `'token_type' => 'Bearer'` for Keycloak.
   Without `issuer` and `audience` the middleware throws at boot.
2. **Every scope in `scopes` is now required**, not any one of them. Before upgrading, check in your identity
   provider that the tokens of each client in `audience` carry all of them. In Keycloak, a scope such as `email` or
   `profile` can be an optional client scope, and then a token carries it only when the client asks for it.
3. **A token that fails verification gets a 401**, not a 400, with a fixed message instead of the library's.

## The verified token

Every request the middleware lets through carries the verified token's claims as the `kipchak.auth.token`
request attribute (`AuthJWKS::ATTRIBUTE_TOKEN`). Requests on ignored paths do not. The token is also still stored
in the container under `token` for compatibility; in FrankenPHP worker mode that entry outlives the request, so
prefer the attribute. Usage Metering and Subashi Pro quotas read it through `kipchak/identity`.

## Tests

```bash
composer install
./vendor/bin/phpunit
```

## What is a Kipchak Middleware?

Kipchak Middleware is a standard PHP PSR-15 middleware.

Middleware is a component that sits between the request and response of a web application, allowing for interception
and modification of the request and response data. In the context of Kipchak, middleware can be used to handle errors,
authentication, and other cross-cutting concerns that are common across one or more API endpoints.
