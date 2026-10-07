<?php

namespace Kipchak\Middleware\Auth\JWKS\Tests\Unit\Handlers;

use Firebase\JWT\JWT as FirebaseJWT;
use Kipchak\Driver\Config\Config;
use Kipchak\Driver\Filecache\Filecache;
use Kipchak\Driver\Logger\Logger;
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
 * a token signed with the matching key, a downstream route that records what it received.
 */
final class AuthJWKSTest extends TestCase
{
    private string $privateKey = '';
    private Container $container;
    public ?ServerRequestInterface $received = null;

    protected function setUp(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $this->privateKey);
        $rsa = openssl_pkey_get_details($key)['rsa'];
        $base64url = fn (string $bytes) => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

        $jwksFile = tempnam(sys_get_temp_dir(), 'jwks');
        file_put_contents($jwksFile, json_encode(['keys' => [[
            'kty' => 'RSA', 'kid' => 'test-key', 'alg' => 'RS256', 'use' => 'sig',
            'n' => $base64url($rsa['n']), 'e' => $base64url($rsa['e']),
        ]]]));

        $this->container = new Container();
        $this->container->set('drivers.config', ['kipchak.auth.jwks' => [
            'enabled' => true,
            'ignore_options' => true,
            'ignore_paths' => ['/status'],
            'jwksUri' => $jwksFile,
            'validate_scopes' => true,
            'scopes' => ['email'],
        ]]);
        $this->container->set('drivers.logger', new MonoLogger('test', [new NullHandler()]));
        $this->container->set('drivers.cache.file', new FilesystemAdapter('jwks-' . bin2hex(random_bytes(4)), 0, sys_get_temp_dir() . '/jwks-test-cache'));
        foreach ([Config::class, Logger::class, Filecache::class] as $driver) {
            (new \ReflectionProperty($driver, 'container'))->setValue(null, $this->container);
        }
        $this->received = null;
    }

    private function token(array $claims = [], string $kid = 'test-key'): string
    {
        return FirebaseJWT::encode($claims + ['sub' => 'user-1', 'scope' => 'openid email', 'exp' => time() + 300], $this->privateKey, 'RS256', $kid);
    }

    private function call(string $path = '/v1/things', ?string $token = null, string $method = 'GET'): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest($method, $path);
        if ($token !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $token);
        }
        $test = $this;

        return (new AuthJWKS($this->container))($request, new class ($test) implements RequestHandlerInterface {
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

    public function testTheVerifiedTokenIsOnTheRequest(): void
    {
        $this->assertSame(200, $this->call(token: $this->token(['sub' => 'user-42', 'azp' => 'web-app']))->getStatusCode());

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
        $this->assertNotSame(200, $this->call(token: $this->token(['exp' => time() - 3600]))->getStatusCode());
        $this->assertNotSame(200, $this->call(token: $this->token(kid: 'unknown-key'))->getStatusCode());
        $this->assertSame(401, $this->call(token: $this->token(['scope' => 'openid']))->getStatusCode());
        $this->assertNull($this->received);
    }

    public function testATokenWithoutAScopeClaimIsRejectedNotAnError(): void
    {
        $token = FirebaseJWT::encode(['sub' => 'u', 'exp' => time() + 300], $this->privateKey, 'RS256', 'test-key');

        $this->assertSame(401, $this->call(token: $token)->getStatusCode());
    }
}
