<?php

use function Kipchak\Core\env;

return [
    'enabled' => false, // true authenticates every request; or attach the middleware to a route group instead
    'ignore_options' => true, // let CORS preflight (OPTIONS) requests through without a token
    'ignore_paths' => [
        '/status',
    ],
    // The JWKS endpoint of your identity provider.
    'jwksUri' => env('JWKS_URI', 'https://idp.example.com/realms/example/protocol/openid-connect/certs'),
    // Optional. Seconds a fetched key set is trusted before it is fetched again; 86400 when left out. 3600 or less
    // means a key the identity provider withdraws stops being accepted within the hour (SR-2026-013).
    'key_set_ttl' => 3600,
    // Required. The exact iss of the tokens you accept. For Keycloak: https://<host>/realms/<realm>.
    'issuer' => env('JWKS_ISSUER', 'https://idp.example.com/realms/example'),
    // Required. The client IDs whose tokens this API accepts, matched against the token's aud or azp claim.
    // Keycloak access tokens carry the client in azp; their aud is often just "account".
    'audience' => array_filter(explode(',', env('JWKS_AUDIENCE', 'example-client'))),
    // Optional. Keycloak sets typ to "Bearer" on access tokens and "ID" on ID tokens, so this refuses ID tokens.
    // Leave it out for identity providers that put no typ claim in the token, such as Entra ID.
    'token_type' => 'Bearer',
    'validate_scopes' => true, // check the scopes below unless a route passes its own
    // A token must carry every one of these scopes.
    'scopes' => [
        'email',
        'profile',
    ],
];
