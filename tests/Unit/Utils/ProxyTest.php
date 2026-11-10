<?php

namespace Kipchak\Middleware\Auth\JWKS\Tests\Unit\Utils;

use Kipchak\Middleware\Auth\JWKS\Exceptions\ConfigurationException;
use Kipchak\Middleware\Auth\JWKS\Utils\Proxy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The proxy configuration and its stream options. tests/Proxy runs the same against a real proxy.
 */
final class ProxyTest extends TestCase
{
    public function testNoProxyBlockOrAnEmptyUrlMeansNoProxy(): void
    {
        $this->assertNull(Proxy::fromConfig([]));
        $this->assertNull(Proxy::fromConfig(['proxy' => []]));
        $this->assertNull(Proxy::fromConfig(['proxy' => ['url' => '', 'no_proxy' => 'localhost']]));
    }

    /** @return array<string, array{mixed}> */
    public static function unusableProxies(): array
    {
        return [
            'not an array' => ['http://proxy:3128'],
            'https proxy' => [['url' => 'https://proxy:3128']],
            'socks proxy' => [['url' => 'socks5://proxy:1080']],
            'no host' => [['url' => 'http://']],
        ];
    }

    #[DataProvider('unusableProxies')]
    public function testAnUnusableProxyIsRefused(mixed $proxy): void
    {
        $this->expectException(ConfigurationException::class);
        Proxy::fromConfig(['proxy' => $proxy]);
    }

    public function testHttpsIsTunnelledAndHttpIsSentAsAFullUri(): void
    {
        $proxy = Proxy::fromConfig(['proxy' => ['url' => 'http://proxy.internal:3128']]);

        $this->assertSame(['proxy' => 'tcp://proxy.internal:3128', 'request_fulluri' => false], $proxy->httpOptions('https://idp.example.com/certs'));
        $this->assertSame(['proxy' => 'tcp://proxy.internal:3128', 'request_fulluri' => true], $proxy->httpOptions('http://idp.example.com/certs'));
        $this->assertSame('tcp://proxy.internal:80', Proxy::fromConfig(['proxy' => ['url' => 'http://proxy.internal']])->httpOptions('https://a.b/c')['proxy']);
    }

    public function testCredentialsBecomeProxyAuthorizationAndAreNeverDescribed(): void
    {
        $fromUrl = Proxy::fromConfig(['proxy' => ['url' => 'http://jwks%40corp:p%3Ass@proxy.internal:3128']]);
        $this->assertSame('Proxy-Authorization: Basic ' . base64_encode('jwks@corp:p:ss'), $fromUrl->httpOptions('https://a.b/c')['header']);
        $this->assertSame('proxy.internal:3128', $fromUrl->describe());

        // Explicit keys take the place of credentials in the URL.
        $explicit = Proxy::fromConfig(['proxy' => ['url' => 'http://old:old@proxy.internal:3128', 'username' => 'jwks', 'password' => 'secret']]);
        $this->assertSame('Proxy-Authorization: Basic ' . base64_encode('jwks:secret'), $explicit->httpOptions('https://a.b/c')['header']);

        $this->assertArrayNotHasKey('header', Proxy::fromConfig(['proxy' => ['url' => 'http://proxy.internal:3128']])->httpOptions('https://a.b/c'));
    }

    /** @return array<string, array{string|array, string, bool}> */
    public static function noProxyCases(): array
    {
        return [
            'exact host' => ['idp.internal', 'https://idp.internal/certs', true],
            'subdomain of a domain' => ['corp.example', 'https://idp.corp.example/certs', true],
            'subdomain, leading dot' => ['.corp.example', 'https://idp.corp.example/certs', true],
            'the domain itself, leading dot' => ['.corp.example', 'https://corp.example/certs', true],
            'not a suffix match' => ['example', 'https://notexample/certs', false],
            'another host' => ['idp.internal', 'https://idp.example.com/certs', false],
            'with a port' => ['localhost:8443', 'https://localhost:8443/certs', true],
            'case and spaces' => [' IDP.Internal , other', 'https://idp.internal/certs', true],
            'everything' => ['*', 'https://idp.example.com/certs', true],
            'a list' => [['idp.internal', 'other'], 'https://other/certs', true],
            'empty list' => ['', 'https://idp.internal/certs', false],
            'a file is never proxied' => ['', '/tmp/jwks.json', true],
        ];
    }

    #[DataProvider('noProxyCases')]
    public function testNoProxy(string|array $noProxy, string $uri, bool $direct): void
    {
        $proxy = Proxy::fromConfig(['proxy' => ['url' => 'http://proxy.internal:3128', 'no_proxy' => $noProxy]]);
        $this->assertSame($direct, $proxy->bypasses($uri));
    }
}
