<?php

namespace Kipchak\Middleware\Auth\JWKS\Tests\Unit\Handlers;

use Firebase\JWT\JWT as FirebaseJWT;
use Kipchak\Driver\Config\Config;
use Kipchak\Driver\Filecache\Filecache;
use Kipchak\Driver\Logger\Logger;
use Kipchak\Middleware\Auth\JWKS\Exceptions\ConfigurationException;
use Kipchak\Middleware\Auth\JWKS\Handlers\AuthJWKS;
use Monolog\Handler\NullHandler;
use Monolog\Logger as MonoLogger;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

/**
 * The handler as an API uses it: a JWKS document (here a local file, as an identity provider would publish it),
 * tokens signed with generated keys, a downstream route that records what it received.
 */
final class AuthJWKSTest extends TestCase
{
    private const ISSUER = 'https://idp.example.com/realms/example';

    /** @var array<string, string> private keys in PEM, by kid */
    private array $privateKeys = [];
    /** @var array<string, array> public keys as JWKs, by kid */
    private array $publicKeys = [];
    private string $jwksFile = '';
    private Container $container;
    public ?ServerRequestInterface $received = null;

    protected function setUp(): void
    {
        $this->jwksFile = tempnam(sys_get_temp_dir(), 'jwks');
        $this->publishKeys('test-key');

        $this->container = new Container();
        $this->configure();
        $this->container->set('drivers.logger', new MonoLogger('test', [new NullHandler()]));
        $this->container->set('drivers.cache.file', new FilesystemAdapter('jwks-' . bin2hex(random_bytes(4)), 0, sys_get_temp_dir() . '/jwks-test-cache'));
        foreach ([Config::class, Logger::class, Filecache::class] as $driver) {
            (new \ReflectionProperty($driver, 'container'))->setValue(null, $this->container);
        }
        $this->received = null;
    }

    private function configure(array $overrides = [], array $remove = []): void
    {
        $config = $overrides + [
            'enabled' => true,
            'ignore_options' => true,
            'ignore_paths' => ['/status'],
            'jwksUri' => $this->jwksFile,
            'issuer' => self::ISSUER,
            'audience' => ['web-app'],
            'token_type' => 'Bearer',
            'validate_scopes' => true,
            'scopes' => ['email'],
        ];
        $this->container->set('drivers.config', ['kipchak.auth.jwks' => array_diff_key($config, array_flip($remove))]);
    }

    /** Generates any keys not generated yet and publishes exactly these kids in the JWKS document. */
    private function publishKeys(string ...$kids): void
    {
        $base64url = fn (string $bytes) => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
        foreach ($kids as $kid) {
            if (!isset($this->privateKeys[$kid])) {
                $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
                openssl_pkey_export($key, $this->privateKeys[$kid]);
                $rsa = openssl_pkey_get_details($key)['rsa'];
                $this->publicKeys[$kid] = ['kty' => 'RSA', 'kid' => $kid, 'alg' => 'RS256', 'use' => 'sig',
                    'n' => $base64url($rsa['n']), 'e' => $base64url($rsa['e'])];
            }
        }
        file_put_contents($this->jwksFile, json_encode(['keys' => array_map(fn ($kid) => $this->publicKeys[$kid], $kids)]));
    }

    /** An access token as Keycloak issues one to the web-app client, unless the claims say otherwise. */
    private function token(array $claims = [], string $kid = 'test-key', ?string $signWith = null): string
    {
        $this->publishKeysIfMissing($signWith ?? $kid);

        return FirebaseJWT::encode($claims + [
            'iss' => self::ISSUER, 'aud' => 'account', 'azp' => 'web-app', 'typ' => 'Bearer',
            'sub' => 'user-1', 'scope' => 'openid email', 'exp' => time() + 300,
        ], $this->privateKeys[$signWith ?? $kid], 'RS256', $kid);
    }

    /** Generates a key for signing without publishing it. */
    private function publishKeysIfMissing(string $kid): void
    {
        if (!isset($this->privateKeys[$kid])) {
            $published = json_decode(file_get_contents($this->jwksFile), true)['keys'] ?? [];
            $this->publishKeys($kid);
            file_put_contents($this->jwksFile, json_encode(['keys' => $published]));
        }
    }

    private function call(string $path = '/v1/things', ?string $token = null, string $method = 'GET', array $scopes = []): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest($method, $path);
        if ($token !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $token);
        }
        $test = $this;

        return (new AuthJWKS($this->container, $scopes))($request, new class ($test) implements RequestHandlerInterface {
            public function __construct(private AuthJWKSTest $test)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->test->received = $request;

                return (new ResponseFactory())->createResponse(200);
            }
        });
    }

    private function body(ResponseInterface $response): array
    {
        return json_decode((string) $response->getBody(), true);
    }

    public function testTheVerifiedTokenIsOnTheRequest(): void
    {
        $this->assertSame(200, $this->call(token: $this->token(['sub' => 'user-42']))->getStatusCode());

        $token = $this->received->getAttribute(AuthJWKS::ATTRIBUTE_TOKEN);
        $this->assertSame('user-42', $token->sub);
        $this->assertSame('web-app', $token->azp);
        $this->assertSame('kipchak.auth.token', AuthJWKS::ATTRIBUTE_TOKEN);
        $this->assertSame('user-42', $this->container->get('token')->sub, 'the container entry is kept for compatibility');
    }

    public function testIgnoredRequestsCarryNoToken(): void
    {
        $this->assertSame(200, $this->call('/status')->getStatusCode());
        $this->assertNull($this->received->getAttribute(AuthJWKS::ATTRIBUTE_TOKEN));
    }

    public function testRejectedTokensNeverReachTheRoute(): void
    {
        $this->assertSame(401, $this->call()->getStatusCode());
        $this->assertSame(401, $this->call(token: $this->token(['exp' => time() - 3600]))->getStatusCode());
        $this->assertSame(401, $this->call(token: $this->token(kid: 'unknown-key'))->getStatusCode());
        $this->assertSame(403, $this->call(token: $this->token(['scope' => 'openid']))->getStatusCode(), 'valid, but without the required scope');
        $this->assertNull($this->received);
    }

    public function testATokenWithoutAScopeClaimIsRejectedNotAnError(): void
    {
        $token = FirebaseJWT::encode(['iss' => self::ISSUER, 'azp' => 'web-app', 'typ' => 'Bearer', 'sub' => 'u', 'exp' => time() + 300],
            $this->privateKeys['test-key'], 'RS256', 'test-key');

        // A valid token with no scope claim has none of the required scopes: refused with 403, not a 500.
        $this->assertSame(403, $this->call(token: $token)->getStatusCode());
    }

    public function testATokenForAnotherClientIsRejected(): void
    {
        $this->assertSame(401, $this->call(token: $this->token(['azp' => 'other-app']))->getStatusCode());
        $this->assertSame(401, $this->call(token: $this->token(['azp' => 'other-app', 'aud' => ['account', 'other-api']]))->getStatusCode());
        $this->assertNull($this->received);

        // Controls: the accepted client in azp, or in aud as a string or a list.
        $this->assertSame(200, $this->call(token: $this->token())->getStatusCode());
        $this->assertSame(200, $this->call(token: $this->token(['azp' => 'other-app', 'aud' => 'web-app']))->getStatusCode());
        $this->assertSame(200, $this->call(token: $this->token(['azp' => 'other-app', 'aud' => ['account', 'web-app']]))->getStatusCode());
    }

    public function testAnIdTokenIsRejected(): void
    {
        // Keycloak's ID tokens carry the client in aud and azp, so only typ tells them apart from access tokens.
        $idToken = $this->token(['typ' => 'ID', 'aud' => 'web-app']);
        $this->assertSame(401, $this->call(token: $idToken)->getStatusCode());
        $this->assertNull($this->received);

        // Control: without a configured token type, typ is not checked (for providers that set no typ claim).
        $this->configure(remove: ['token_type']);
        $this->assertSame(200, $this->call(token: $idToken)->getStatusCode());
    }

    public function testATokenFromAnotherIssuerIsRejected(): void
    {
        $this->assertSame(401, $this->call(token: $this->token(['iss' => 'https://idp.example.com/realms/other']))->getStatusCode());
        $this->assertSame(401, $this->call(token: $this->token(['iss' => self::ISSUER . '/']))->getStatusCode(), 'iss is an exact match');
        $this->assertNull($this->received);

        $this->assertSame(200, $this->call(token: $this->token(['iss' => self::ISSUER]))->getStatusCode());
    }

    public function testEveryRequiredScopeMustBePresent(): void
    {
        $this->configure(['scopes' => ['email', 'profile']]);
        $this->assertSame(403, $this->call(token: $this->token(['scope' => 'openid email']))->getStatusCode());
        $this->assertSame(200, $this->call(token: $this->token(['scope' => 'openid email profile']))->getStatusCode());

        // Scopes passed on a route replace the configured ones and are all required too.
        $this->assertSame(403, $this->call(token: $this->token(['scope' => 'email profile']), scopes: ['orders:read', 'email'])->getStatusCode());
        $this->assertSame(200, $this->call(token: $this->token(['scope' => 'orders:read email']), scopes: ['orders:read', 'email'])->getStatusCode());
    }

    public function testAVerificationFailureIsA401WithAFixedMessage(): void
    {
        // Signed with a key that is not the published one under that kid: the signature does not verify.
        $this->publishKeysIfMissing('impostor');
        $forged = $this->token(kid: 'test-key', signWith: 'impostor');
        $response = $this->call(token: $forged);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(AuthJWKS::MESSAGE_INVALID_TOKEN, $this->body($response)['data']);

        $response = $this->call(token: 'not.a.jwt');
        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(AuthJWKS::MESSAGE_INVALID_TOKEN, $this->body($response)['data']);
        $this->assertNull($this->received);
    }

    public function testRefusalsCarryTheStatusesMiddlewareErrorUses(): void
    {
        $missing = $this->body($this->call());
        $this->assertSame([401, 'UNAUTHENTICATED'], [$missing['code'], $missing['status']]);

        $invalid = $this->body($this->call(token: $this->token(['exp' => time() - 3600])));
        $this->assertSame([401, 'UNAUTHENTICATED', AuthJWKS::MESSAGE_INVALID_TOKEN], [$invalid['code'], $invalid['status'], $invalid['data']]);

        $scope = $this->body($this->call(token: $this->token(['scope' => 'openid'])));
        $this->assertSame([403, 'INSUFFICIENT_PRIVILEGES'], [$scope['code'], $scope['status']]);

        // Control: the label 1.41 and earlier wrote, through Response::json(), which this release no longer uses.
        $this->assertSame('UNAUTHORIZED', json_decode((string) \Kipchak\Core\Components\Http\Response::json(new \Slim\Psr7\Response(), '', 401)->getBody(), true)['status']);
    }

    public function testAShorterKeySetTtlFetchesTheSetAgainOnceItExpires(): void
    {
        $this->configure(['key_set_ttl' => 1]);
        $token = $this->token();
        $this->assertSame(200, $this->call(token: $token)->getStatusCode()); // caches the set with test-key

        // The identity provider withdraws test-key.
        $this->publishKeys('other-key');
        $this->assertSame(200, $this->call(token: $token)->getStatusCode(), 'Within the TTL the cached set still holds it');

        sleep(2);
        $this->assertSame(401, $this->call(token: $token)->getStatusCode(), 'After the TTL the set is fetched again, without it');
    }

    public function testControlTheDefaultTtlKeepsTheSetBeyondThatTime(): void
    {
        $token = $this->token();
        $this->assertSame(200, $this->call(token: $token)->getStatusCode());

        $this->publishKeys('other-key');
        sleep(2);
        $this->assertSame(200, $this->call(token: $token)->getStatusCode());
    }

    public function testChangingTheTtlDoesNotKeepASetCachedUnderTheOldOne(): void
    {
        $token = $this->token();
        $this->assertSame(200, $this->call(token: $token)->getStatusCode()); // cached for the default 86400 seconds
        $this->publishKeys('other-key');

        $this->assertSame(200, $this->call(token: $token)->getStatusCode(), 'Control: the same TTL reads the cached set');

        $this->configure(['key_set_ttl' => 3600]);
        $this->assertSame(401, $this->call(token: $token)->getStatusCode(), 'A new TTL fetches the set at once');
    }

    public function testAnInvalidKeySetTtlFailsAtBoot(): void
    {
        foreach ([0, -60, '3600', 3600.5, null] as $invalid) {
            $this->configure(['key_set_ttl' => $invalid]);
            try {
                new AuthJWKS($this->container);
                $this->fail('The middleware was built with key_set_ttl ' . var_export($invalid, true) . '.');
            } catch (ConfigurationException $e) {
                $this->assertStringContainsString('"key_set_ttl"', $e->getMessage());
            }
        }

        $this->configure(['key_set_ttl' => 3600]);
        $this->assertInstanceOf(AuthJWKS::class, new AuthJWKS($this->container));
    }

    public function testAFailedFetchIsNotCached(): void
    {
        $token = $this->token();
        $published = file_get_contents($this->jwksFile);

        unlink($this->jwksFile);
        $this->assertSame(401, $this->call(token: $token)->getStatusCode());
        file_put_contents($this->jwksFile, '{"error": "temporarily unavailable"}');
        $this->assertSame(401, $this->call(token: $token)->getStatusCode());

        // The key set is back: the next request fetches it, because neither failure was cached.
        file_put_contents($this->jwksFile, $published);
        $this->assertSame(200, $this->call(token: $token)->getStatusCode());
    }

    public function testAValidKeySetIsCached(): void
    {
        // Control for the test above: once a valid set is cached, the document is not read again.
        $token = $this->token();
        $this->assertSame(200, $this->call(token: $token)->getStatusCode());
        unlink($this->jwksFile);
        $this->assertSame(200, $this->call(token: $token)->getStatusCode());
    }

    public function testAnUnknownKidFetchesTheKeySetOnceAgain(): void
    {
        $this->assertSame(200, $this->call(token: $this->token())->getStatusCode()); // caches the set with test-key only

        // The identity provider rotates: it now publishes rotated-key as well.
        $this->publishKeys('test-key', 'rotated-key');
        $this->assertSame(200, $this->call(token: $this->token(kid: 'rotated-key'))->getStatusCode());
        $this->assertSame(200, $this->call(token: $this->token())->getStatusCode(), 'the old key still works');
    }

    public function testRefetchingIsRateLimited(): void
    {
        $this->assertSame(200, $this->call(token: $this->token())->getStatusCode());

        // An unknown kid causes one refetch, which finds nothing new.
        $this->assertSame(401, $this->call(token: $this->token(kid: 'unknown-key'))->getStatusCode());

        // A key published straight after is not fetched again within the interval: at most one refetch.
        $this->publishKeys('test-key', 'rotated-key');
        $this->assertSame(401, $this->call(token: $this->token(kid: 'rotated-key'))->getStatusCode());
    }

    public function testTheOldConfigurationFailsAtBoot(): void
    {
        // The configuration of 1.40 and earlier, with neither issuer nor audience.
        $this->configure(remove: ['issuer', 'audience', 'token_type']);

        try {
            new AuthJWKS($this->container);
            $this->fail('The middleware was built without an issuer or an audience.');
        } catch (ConfigurationException $e) {
            $this->assertStringContainsString('"issuer"', $e->getMessage());
            $this->assertStringContainsString('"audience"', $e->getMessage());
        }
    }

    public function testEachMissingKeyIsNamed(): void
    {
        foreach (['issuer' => [], 'audience' => []] as $missing => $_) {
            $this->configure(remove: [$missing]);
            try {
                new AuthJWKS($this->container);
                $this->fail("The middleware was built without {$missing}.");
            } catch (ConfigurationException $e) {
                $this->assertStringContainsString("\"{$missing}\"", $e->getMessage());
            }
        }
        foreach ([['audience' => []], ['audience' => 'web-app'], ['audience' => ['']], ['issuer' => '']] as $invalid) {
            $this->configure($invalid);
            try {
                new AuthJWKS($this->container);
                $this->fail('The middleware was built with ' . json_encode($invalid));
            } catch (ConfigurationException) {
            }
        }
    }
}
