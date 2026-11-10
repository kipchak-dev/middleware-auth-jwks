<?php

namespace Kipchak\Middleware\Auth\JWKS\Handlers;

use Kipchak\Core\Components\Http;
use Kipchak\Driver\Filecache\Filecache;
use Kipchak\Middleware\Auth\JWKS\Exceptions\ConfigurationException;
use Kipchak\Middleware\Auth\JWKS\Exceptions\KeySetUnavailableException;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;
use Kipchak\Middleware\Auth\JWKS\Utils\JWKS;
use Kipchak\Middleware\Auth\JWKS\Utils\Proxy;
use Symfony\Contracts\Cache\ItemInterface;
use Monolog\Logger as Log;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Throwable;
use Kipchak\Driver\Config\Config;
use Kipchak\Driver\Logger\Logger;

class AuthJWKS
{
    /**
     * The verified token (the decoded claims, as a \stdClass) on every request this middleware lets through.
     * Read it with $request->getAttribute(AuthJWKS::ATTRIBUTE_TOKEN). Requests on ignored paths do not carry it.
     */
    public const ATTRIBUTE_TOKEN = 'kipchak.auth.token';

    /**
     * The only message a client receives when its token fails verification, whatever the reason. The reason is logged.
     */
    public const MESSAGE_INVALID_TOKEN = 'Invalid token';

    /**
     * How long a valid key set is cached unless key_set_ttl says otherwise, and the shortest interval between two
     * fetches made because a token named a key the cached set does not have.
     */
    public const DEFAULT_KEY_SET_TTL = 86400;
    private const REFETCH_INTERVAL = 60;

    private int $keySetTtl;

    public ContainerInterface $container;

    private Log $log;

    private FilesystemAdapter $cache;

    private array $scopes;

    private ?Proxy $proxy;

    public function __construct(ContainerInterface $container, array $scopes = [])
    {
        $this->container = $container;
        $this->cache = Filecache::get();
        $this->log = Logger::get();
        $this->scopes = $scopes;
        $authConfig = Config::get('kipchak.auth.jwks') ?? [];
        self::assertConfigured($authConfig);
        $this->keySetTtl = $authConfig['key_set_ttl'] ?? self::DEFAULT_KEY_SET_TTL;
        $this->proxy = Proxy::fromConfig($authConfig);
    }

    /**
     * Refuses a configuration that would accept tokens issued for another client or by another issuer.
     *
     * @throws ConfigurationException
     */
    public static function assertConfigured(array $authConfig): void
    {
        $missing = [];
        if (!is_string($authConfig['issuer'] ?? null) || $authConfig['issuer'] === '') {
            $missing[] = '"issuer" (the exact iss of your identity provider, e.g. https://idp.example.com/realms/example)';
        }
        $audience = $authConfig['audience'] ?? null;
        if (!is_array($audience) || $audience === [] || array_filter($audience, fn ($a) => !is_string($a) || $a === '') !== []) {
            $missing[] = '"audience" (a non-empty list of the client IDs whose tokens this API accepts)';
        }
        if (!is_string($authConfig['jwksUri'] ?? null) || $authConfig['jwksUri'] === '') {
            $missing[] = '"jwksUri"';
        }
        if (array_key_exists('key_set_ttl', $authConfig) && (!is_int($authConfig['key_set_ttl']) || $authConfig['key_set_ttl'] < 1)) {
            $missing[] = 'a valid "key_set_ttl" (a whole number of seconds, at least 1; omit it for 86400)';
        }
        if ($missing !== []) {
            throw new ConfigurationException('kipchak/middleware-auth-jwks refuses to run without ' . implode(' and ', $missing)
                . ' in config/kipchak.auth.jwks.php. See https://kipchak.dev/docs/mw-auth-jwks.');
        }
    }

    /**
     * JWKS Authentication middleware invokable class
     *
     * @param ServerRequestInterface $request PSR-7 request
     * @param RequestHandlerInterface $handler PSR-15 request handler
     *
     * @return Response
     */
    public function __invoke(ServerRequestInterface $request, RequestHandlerInterface $handler): Response
    {
        $authConfig = Config::get('kipchak.auth.jwks');
        $response = new Response();

        if (
            (isset($authConfig['ignore_options']) && $request->getMethod() === 'OPTIONS' && $authConfig['ignore_options']) ||
            (isset($authConfig['ignore_paths']) && in_array($request->getUri()->getPath(), $authConfig['ignore_paths']))
        ) {
            return $handler->handle($request);
        }

        if (!isset($request->getHeader('Authorization')[0])) {
            return Http\Response::error($response, 'No token found', 401);
        }
        if (!preg_match('/Bearer\s(\S+)/', $request->getHeader('Authorization')[0], $matches)) {
            return Http\Response::error($response, 'No Bearer token found in the Authorization header', 401);
        }
        $jwt = $matches[1];

        try {
            $token = JWKS::decode($jwt, $this->keySet($authConfig['jwksUri'], JWKS::keyId($jwt)));
        } catch (KeySetUnavailableException $e) {
            $this->log->error('JWKS: ' . $e->getMessage());

            return Http\Response::error($response, self::MESSAGE_INVALID_TOKEN, 401);
        } catch (Throwable $e) {
            $this->log->info('JWKS: token rejected: ' . $e->getMessage());

            return Http\Response::error($response, self::MESSAGE_INVALID_TOKEN, 401);
        }

        $problem = JWKS::claimsProblem($token, $authConfig['issuer'], $authConfig['audience'], $authConfig['token_type'] ?? null, time());
        if ($problem !== null) {
            $this->log->info('JWKS: token rejected: ' . $problem);

            return Http\Response::error($response, self::MESSAGE_INVALID_TOKEN, 401);
        }

        // Scopes passed to the middleware on a route take the place of the configured ones.
        $required = $this->scopes !== [] ? $this->scopes : (($authConfig['validate_scopes'] ?? false) ? ($authConfig['scopes'] ?? []) : []);
        if ($required !== [] && !JWKS::hasScopes((string) ($token->scope ?? ''), $required)) {
            // The token is valid but does not allow this request: 403, insufficient scope (RFC 6750 §3.1).
            return Http\Response::error($response, 'Missing required scope(s)', 403);
        }

        // Kept for compatibility. Prefer the request attribute: in FrankenPHP worker mode the container
        // outlives the request, so this entry still holds the last token on later requests that carry none.
        $this->container->set('token', function (ContainerInterface $c) use ($token) {
            return $token;
        });

        // If we got this far, we can let the token through, carrying its verified claims.
        return $handler->handle($request->withAttribute(self::ATTRIBUTE_TOKEN, $token));
    }

    /**
     * The key set, from the cache when it holds one. Only a valid key set is cached: a failed fetch caches nothing, so
     * the next request tries again. A token whose kid the cached set does not have causes one new fetch, at most every
     * REFETCH_INTERVAL seconds, so that a key rotated at the identity provider is picked up without waiting a day.
     *
     * @throws KeySetUnavailableException
     */
    private function keySet(string $jwksUri, ?string $kid): array
    {
        // The lifetime is part of the key, so that lowering key_set_ttl takes effect at once rather than once an entry
        // cached under the old lifetime expires.
        $cacheKey = 'jwks.' . sha1($jwksUri) . '.' . $this->keySetTtl;
        $fetch = function (ItemInterface $item) use ($jwksUri): array {
            $item->expiresAfter($this->keySetTtl);
            $this->log->debug('JWKS: cache miss, fetching the key set');

            return $this->fetch($jwksUri); // Throws on failure, and the cache then stores nothing.
        };

        $keySet = $this->cache->get($cacheKey, $fetch);
        if ($kid === null || JWKS::hasKeyId($keySet, $kid)) {
            return $keySet;
        }

        $refetch = $this->cache->getItem($cacheKey . '.refetched');
        if ($refetch->isHit()) {
            return $keySet; // Fetched again recently: the kid is unknown, and the decode will reject the token.
        }
        $refetch->set(time())->expiresAfter(self::REFETCH_INTERVAL);
        $this->cache->save($refetch);

        $this->log->info('JWKS: unknown kid, fetching the key set again');
        $fresh = $this->fetch($jwksUri);
        $item = $this->cache->getItem($cacheKey);
        $this->cache->save($item->set($fresh)->expiresAfter($this->keySetTtl));

        return $fresh;
    }

    /**
     * @throws KeySetUnavailableException
     */
    private function fetch(string $jwksUri): array
    {
        $http = ['timeout' => 5, 'ignore_errors' => false];
        $through = '';
        if ($this->proxy !== null && !$this->proxy->bypasses($jwksUri)) {
            $http += $this->proxy->httpOptions($jwksUri);
            $through = ' through the proxy ' . $this->proxy->describe();
        }
        $body = @file_get_contents($jwksUri, false, stream_context_create(['http' => $http]));
        if ($body === false) {
            throw new KeySetUnavailableException('could not fetch the key set from ' . $jwksUri . $through);
        }
        $keySet = json_decode($body, true);
        if (!is_array($keySet) || !isset($keySet['keys']) || !is_array($keySet['keys']) || $keySet['keys'] === []) {
            throw new KeySetUnavailableException('the document at ' . $jwksUri . ' is not a key set with a non-empty "keys" array');
        }

        return $keySet;
    }
}
