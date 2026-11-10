<?php

namespace Kipchak\Middleware\Auth\JWKS\Tests\Proxy;

use Firebase\JWT\JWT as FirebaseJWT;
use Kipchak\Driver\Config\Config;
use Kipchak\Driver\Filecache\Filecache;
use Kipchak\Driver\Logger\Logger;
use Kipchak\Middleware\Auth\JWKS\Exceptions\ConfigurationException;
use Kipchak\Middleware\Auth\JWKS\Handlers\AuthJWKS;
use Kipchak\Middleware\Auth\JWKS\Tests\Unit\Handlers\Container;
use Monolog\Handler\TestHandler;
use Monolog\Logger as MonoLogger;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

/**
 * The key set fetched through a real outbound proxy (tinyproxy), from an identity provider the test cannot reach
 * directly: jwks.test resolves only inside the proxy's network. Run by tests/Proxy/run.sh, which starts both.
 */
final class ProxyTest extends TestCase
{
    private const ISSUER = 'https://idp.example.com/realms/example';
    private const IDP = 'https://jwks.test/certs';
    private const OPEN_PROXY = 'http://127.0.0.1:18888';
    private const AUTH_PROXY = 'http://127.0.0.1:18889';
    private const UNREACHABLE_PROXY = 'http://127.0.0.1:1';
    private const PASSWORD = 's3cret-proxy-pass';

    private string $privateKey = '';
    private Container $container;
    private TestHandler $log;

    protected function setUp(): void
    {
        $www = getenv('JWKS_PROXY_TEST_WWW');
        if (!is_string($www) || !is_dir($www)) {
            $this->markTestSkipped('Needs the proxies and identity provider of tests/Proxy/run.sh.');
        }

        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $this->privateKey);
        $rsa = openssl_pkey_get_details($key)['rsa'];
        $base64url = fn (string $bytes) => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
        file_put_contents($www . '/certs', json_encode(['keys' => [['kty' => 'RSA', 'kid' => 'test-key', 'alg' => 'RS256',
            'use' => 'sig', 'n' => $base64url($rsa['n']), 'e' => $base64url($rsa['e'])]]]));

        $this->container = new Container();
        $this->log = new TestHandler();
        $this->container->set('drivers.logger', new MonoLogger('test', [$this->log]));
        $this->container->set('drivers.cache.file', new FilesystemAdapter('jwks-' . bin2hex(random_bytes(4)), 0, sys_get_temp_dir() . '/jwks-test-cache'));
        foreach ([Config::class, Logger::class, Filecache::class] as $driver) {
            (new \ReflectionProperty($driver, 'container'))->setValue(null, $this->container);
        }
    }

    public function testTheIdentityProviderIsOnlyReachableThroughTheProxy(): void
    {
        // The premise of every test below: from here, jwks.test does not resolve.
        $this->assertSame('jwks.test', gethostbyname('jwks.test'));
        $this->assertSame(401, $this->call(self::IDP, null)->getStatusCode(), 'fetched with no proxy');
    }

    public function testAnHttpsKeySetIsFetchedThroughTheProxy(): void
    {
        $this->assertSame(200, $this->call(self::IDP, ['url' => self::OPEN_PROXY])->getStatusCode());
    }

    public function testAnHttpKeySetIsFetchedThroughTheProxy(): void
    {
        $this->assertSame(200, $this->call('http://jwks.test/certs', ['url' => self::OPEN_PROXY])->getStatusCode());
    }

    public function testAnUnreachableProxyFailsClosed(): void
    {
        $this->assertSame(401, $this->call(self::IDP, ['url' => self::UNREACHABLE_PROXY])->getStatusCode());
        $this->assertTrue($this->log->hasErrorThatContains('through the proxy 127.0.0.1:1'));
    }

    public function testANoProxyHostIsFetchedDirectly(): void
    {
        // The proxy is unreachable, so only a direct fetch can succeed.
        $proxy = ['url' => self::UNREACHABLE_PROXY, 'no_proxy' => 'example.org, localhost:18443'];
        $this->assertSame(200, $this->call('https://localhost:18443/certs', $proxy)->getStatusCode());
    }

    public function testControlAHostNotInNoProxyGoesThroughTheProxy(): void
    {
        $proxy = ['url' => self::UNREACHABLE_PROXY, 'no_proxy' => 'example.org'];
        $this->assertSame(401, $this->call('https://localhost:18443/certs', $proxy)->getStatusCode());
    }

    public function testProxyCredentialsFromTheUrlOrTheConfiguration(): void
    {
        $this->assertSame(200, $this->call(self::IDP, ['url' => 'http://jwks-user:' . self::PASSWORD . '@127.0.0.1:18889'])->getStatusCode());
        $this->assertSame(200, $this->call(self::IDP, ['url' => self::AUTH_PROXY, 'username' => 'jwks-user', 'password' => self::PASSWORD])->getStatusCode());
    }

    public function testControlTheProxyRefusesMissingOrWrongCredentials(): void
    {
        $this->assertSame(401, $this->call(self::IDP, ['url' => self::AUTH_PROXY])->getStatusCode());
        $this->assertSame(401, $this->call(self::IDP, ['url' => self::AUTH_PROXY, 'username' => 'jwks-user', 'password' => 'wrong'])->getStatusCode());
    }

    public function testCredentialsNeverReachTheLog(): void
    {
        $this->call(self::IDP, ['url' => 'http://jwks-user:' . self::PASSWORD . '@127.0.0.1:1']);
        $this->call(self::IDP, ['url' => self::UNREACHABLE_PROXY, 'username' => 'jwks-user', 'password' => self::PASSWORD]);

        $this->assertNotEmpty($this->log->getRecords());
        foreach ($this->log->getRecords() as $record) {
            $this->assertStringNotContainsString(self::PASSWORD, $record->message);
            $this->assertStringNotContainsString(base64_encode('jwks-user:' . self::PASSWORD), $record->message);
        }
    }

    public function testAnHttpsProxyUrlIsRefusedAtBoot(): void
    {
        // PHP's HTTP stream cannot speak TLS to a proxy, so an https:// proxy would never work.
        $this->expectException(ConfigurationException::class);
        $this->call(self::IDP, ['url' => 'https://127.0.0.1:18888']);
    }

    private function call(string $jwksUri, ?array $proxy): ResponseInterface
    {
        $config = ['enabled' => true, 'jwksUri' => $jwksUri, 'issuer' => self::ISSUER, 'audience' => ['web-app'],
            'token_type' => 'Bearer', 'validate_scopes' => false];
        if ($proxy !== null) {
            $config['proxy'] = $proxy;
        }
        $this->container->set('drivers.config', ['kipchak.auth.jwks' => $config]);
        // A new cache for each call, so that every call fetches the key set.
        $this->container->set('drivers.cache.file', new FilesystemAdapter('jwks-' . bin2hex(random_bytes(4)), 0, sys_get_temp_dir() . '/jwks-test-cache'));

        $token = FirebaseJWT::encode(['iss' => self::ISSUER, 'aud' => 'account', 'azp' => 'web-app', 'typ' => 'Bearer',
            'sub' => 'user-1', 'scope' => 'openid email', 'exp' => time() + 300], $this->privateKey, 'RS256', 'test-key');
        $request = (new ServerRequestFactory())->createServerRequest('GET', '/v1/things')->withHeader('Authorization', 'Bearer ' . $token);

        return (new AuthJWKS($this->container))($request, new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new ResponseFactory())->createResponse(200);
            }
        });
    }
}
