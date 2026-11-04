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
    'validate_scopes' => true, // check the scopes below unless a route passes its own
    'scopes' => [
        'email',
        'profile',
    ],
];
