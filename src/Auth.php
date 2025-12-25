<?php

namespace Kipchak\Middleware\Auth;

use Kipchak\Core\Interfaces;
use Kipchak\Driver\Config\Driver as Config;
use Kipchak\Middleware\Auth\Handlers\AuthJwks;
use Kipchak\Middleware\Auth\Handlers\AuthKey;
use Slim\App;

class Auth implements Interfaces\Middleware
{
    public static function initialise(App $app): void
    {
        $container = $app->getContainer();
        if (!empty(Config::get('kipchak.auth'))) {
            $auth = Config::get('kipchak.auth');
            if ($auth['jwks']['enabled']) {
                // Enable JWKS globally
                $app->add(new AuthJwks($container));
            }

            if ($auth['key']['enabled']) {
                // Enable Key based auth globally
                $app->add(new AuthKey($container));

            }
        }

    }

}