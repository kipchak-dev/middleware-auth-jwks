<?php

namespace Kipchak\Middleware\Auth\JWKS\Utils;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

class JWKS
{
    public static function decode(string $jwt, array $jwks): \stdClass
    {
        // Set leeway to allow for clock sync changes between client and server.
        JWT::$leeway = 1;

        // Verifies the signature against the key set, and exp, nbf and iat. The claims are checked by claimsProblem().
        return JWT::decode($jwt,
            JWK::parseKeySet($jwks)
        );

    }

    /**
     * The kid in the token's header, read without verifying anything, to know whether the key set has its key.
     */
    public static function keyId(string $jwt): ?string
    {
        $header = json_decode(JWT::urlsafeB64Decode(explode('.', $jwt)[0]), true);

        return is_array($header) && is_string($header['kid'] ?? null) ? $header['kid'] : null;
    }

    public static function hasKeyId(array $jwks, string $kid): bool
    {
        foreach ($jwks['keys'] ?? [] as $key) {
            if (($key['kid'] ?? null) === $kid) {
                return true;
            }
        }

        return false;
    }

    /**
     * Why a verified token must still be refused, or null when its claims are acceptable.
     *
     * - iss must equal the configured issuer exactly.
     * - One of the configured audiences must be in aud (a string or a list) or equal azp. Keycloak puts the client a
     *   token was issued to in azp; its aud is often only "account".
     * - With a token type configured, typ must equal it: Keycloak sets "Bearer" on access tokens and "ID" on ID tokens.
     * - exp must be present and in the future.
     */
    public static function claimsProblem(\stdClass $token, string $issuer, array $audience, ?string $tokenType, int $now): ?string
    {
        if (!isset($token->exp) || !is_numeric($token->exp)) {
            return 'the token has no expiry';
        }
        if ($token->exp < $now) {
            return 'the token has expired';
        }
        if (($token->iss ?? null) !== $issuer) {
            return 'the issuer does not match';
        }
        $audiences = array_merge(is_array($token->aud ?? null) ? $token->aud : [$token->aud ?? null], [$token->azp ?? null]);
        if (array_intersect($audience, array_filter($audiences, 'is_string')) === []) {
            return 'the token was not issued for an accepted audience';
        }
        if ($tokenType !== null && $tokenType !== '' && ($token->typ ?? null) !== $tokenType) {
            return 'the token type is not ' . $tokenType;
        }

        return null;
    }

    /**
     * True when the token carries every required scope.
     */
    public static function hasScopes(string $inToken, array $required): bool
    {
        return array_diff($required, explode(' ', $inToken)) === [];
    }
}
