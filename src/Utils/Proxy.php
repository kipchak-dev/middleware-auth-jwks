<?php

namespace Kipchak\Middleware\Auth\JWKS\Utils;

use Kipchak\Middleware\Auth\JWKS\Exceptions\ConfigurationException;

/**
 * The outbound proxy the key set is fetched through, from the "proxy" block of config/kipchak.auth.jwks.php:
 *
 *   'proxy' => ['url' => 'http://proxy.internal:3128', 'username' => '', 'password' => '', 'no_proxy' => 'idp.internal,.corp'],
 *
 * An https:// key set is fetched through a CONNECT tunnel, and an http:// one as a full URI to the proxy. Credentials,
 * from the URL or from username and password, are sent to the proxy only, as Proxy-Authorization, and never appear in
 * a message: describe() names the proxy by host and port alone.
 */
final class Proxy
{
    private function __construct(
        private readonly string $address,
        private readonly ?string $authorization,
        /** @var list<string> */
        private readonly array $noProxy,
    ) {}

    /**
     * The proxy the configuration names, or null when it names none.
     *
     * @throws ConfigurationException when the "proxy" block cannot be used
     */
    public static function fromConfig(array $authConfig): ?self
    {
        $config = $authConfig['proxy'] ?? null;
        if ($config === null || $config === []) {
            return null;
        }
        if (!is_array($config)) {
            throw new ConfigurationException('"proxy" in config/kipchak.auth.jwks.php must be an array with a "url". See https://kipchak.dev/docs/mw-auth-jwks.');
        }
        $url = $config['url'] ?? '';
        if (!is_string($url) || $url === '') {
            return null; // No proxy configured, as when HTTPS_PROXY is not set.
        }

        $parts = parse_url($url);
        if ($parts === false || !isset($parts['host']) || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'tcp'], true)) {
            // PHP's HTTP stream speaks plain HTTP to the proxy, and tunnels TLS to the identity provider through it.
            throw new ConfigurationException('"proxy.url" must be an http:// URL with a host, such as http://proxy.internal:3128. See https://kipchak.dev/docs/mw-auth-jwks.');
        }

        $username = self::credential($config['username'] ?? null) ?? (isset($parts['user']) ? rawurldecode($parts['user']) : null);
        $password = self::credential($config['password'] ?? null) ?? (isset($parts['pass']) ? rawurldecode($parts['pass']) : null);
        $authorization = $username === null ? null : 'Basic ' . base64_encode($username . ':' . ($password ?? ''));

        return new self('tcp://' . $parts['host'] . ':' . ($parts['port'] ?? 80), $authorization, self::noProxyList($config['no_proxy'] ?? []));
    }

    /**
     * The proxy by host and port, without credentials, for log messages.
     */
    public function describe(): string
    {
        return substr($this->address, strlen('tcp://'));
    }

    /**
     * Whether the URI is fetched directly: a host in no_proxy, or a URI that is not HTTP (a local file in tests).
     */
    public function bypasses(string $uri): bool
    {
        $scheme = strtolower((string) parse_url($uri, PHP_URL_SCHEME));
        $host = strtolower((string) parse_url($uri, PHP_URL_HOST));
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            return true;
        }
        foreach ($this->noProxy as $entry) {
            // "*" matches every host; "example.com" and ".example.com" match it and its subdomains, as curl does.
            if ($entry === '*' || $host === ltrim($entry, '.') || str_ends_with($host, '.' . ltrim($entry, '.'))) {
                return true;
            }
        }

        return false;
    }

    /**
     * The "http" stream context options that send a request for the URI through the proxy.
     */
    public function httpOptions(string $uri): array
    {
        $options = [
            'proxy' => $this->address,
            // A plain http:// request goes to the proxy as a full URI. An https:// one is tunnelled with CONNECT, and
            // the request inside the tunnel keeps its own path.
            'request_fulluri' => strtolower((string) parse_url($uri, PHP_URL_SCHEME)) === 'http',
        ];
        if ($this->authorization !== null) {
            // PHP sends this header to the proxy with CONNECT, and leaves it out of the request to the identity provider.
            $options['header'] = 'Proxy-Authorization: ' . $this->authorization;
        }

        return $options;
    }

    private static function credential(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return list<string>
     */
    private static function noProxyList(mixed $noProxy): array
    {
        $entries = is_array($noProxy) ? $noProxy : explode(',', is_string($noProxy) ? $noProxy : '');
        $entries = array_map(fn ($entry) => strtolower(trim((string) $entry)), $entries);

        // An entry may carry a port (host:443); the match is on the host.
        return array_values(array_filter(array_map(fn ($entry) => preg_replace('/:\d+$/', '', $entry), $entries), fn ($entry) => $entry !== ''));
    }
}
