<?php

namespace Kipchak\Middleware\Auth\Handler;

use Kipchak\Core\Components\Http;
use Kipchak\Driver\Filecache\Driver;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;
use Kipchak\Core\Components\Auth\JWKS;
use Symfony\Contracts\Cache\ItemInterface;
use Monolog\Logger as Log;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Exception;
use Kipchak\Driver\Config\Driver as Config;
use Kipchak\Driver\Logger\Driver as Logger;

class AuthJwks
{
    public ContainerInterface $container;

    private Log $log;

    private FilesystemAdapter $cache;

    private array $scopes;

    public function __construct(ContainerInterface $container, array $scopes = [])
    {
        $this->container = $container;
        $this->cache = Driver::get();
        $this->log = Logger::get();
        $this->scopes = $scopes;

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
        $authConfig = Config::get('kipchak.auth');
        $response = new Response();

        if (
            (isset($authConfig['jwks']['ignore_options']) && $request->getMethod() === 'OPTIONS' && $authConfig['jwks']['ignore_options']) ||
            (isset($authConfig['jwks']['ignore_paths']) && in_array($request->getUri()->getPath(), $authConfig['jwks']['ignore_paths']))
        ) {
            $response = $handler->handle($request);

            return $response;
        }



        if (isset($request->getHeader('Authorization')[0])) {
            $authHeader = $request->getHeader('Authorization')[0];
            if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
                // No Bearer token found.
                return Http\Response::json($response,
                    'No Bearer token found in the Authorization header',
                    401
                );
            } else {
                try {
                    // Bearer token found
                    $jwt = $matches[1];
                    // The URI for the JWKS you wish to cache the results from
                    $jwksUri = $authConfig['jwks']['jwksUri'];

                    $this->log->debug('Using a cache contract to get the JWKS key...');

                    $jwks = $this->cache->get('jwks', function (ItemInterface $item) use ($jwksUri) {
                        $item->expiresAfter(86400);
                        $this->log->debug('Cache miss. Getting JWKS key from the URL');
                        $jwks = json_decode(file_get_contents($jwksUri), true);

                        return $jwks;
                    });

                    $token = JWKS::decode($jwt, $jwks);

                    // Let's check the expiry time on the token before anything else. If expiry is less than the current unit timestamp, reject the token.
                    if (isset($token->exp)) {
                        if ($token->exp < time()) {
                            return Http\Response::json($response,
                                'Token has expired',
                                401
                            );
                        }
                    } else {
                        return Http\Response::json($response,
                            'Token does not have a valid expiry timestamp',
                            401
                        );
                    }

                    // If config says validate scopes and no scopes are passed to the MW, use the default ones
                    if (empty($this->scopes)) {
                        if ($authConfig['jwks']['validate_scopes']) {
                            if (!JWKS::hasScopes($token->scope, $authConfig['jwks']['scopes'])) {
                                return Http\Response::json($response,
                                    'Missing required scope(s)',
                                    401
                                );
                            }
                        }
                    } else {
                        // Custom scopes have been passed, validate those
                        if (!JWKS::hasScopes($token->scope, $this->scopes)) {
                            return Http\Response::json($response,
                                'Missing required scope(s)',
                                401
                            );
                        }
                    }

                    // Add the token to the container so the route can access it if needed
                    $this->container->set('token', function(ContainerInterface $c) use ($token) {
                        return $token;
                    });

                    // If we got this far, we can let the token through
                    $response = $handler->handle($request);

                    return $response;

                } catch (Exception $e) {
                    return Http\Response::json($response,
                        $e->getMessage(),
                        400
                    );
                }
            }
        } else {
            // No Authorization header or JWT auth is disabled in config, so do nothing.
            return Http\Response::json($response,
                'No token found',
                401
            );
        }
    }

}