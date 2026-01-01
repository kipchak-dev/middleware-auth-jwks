<?php

namespace Kipchak\Middleware\Auth\JWKS;

use Kipchak\Core\Interfaces;
use Kipchak\Driver\Config\Config;
use Kipchak\Middleware\Auth\JWKS\Handlers\AuthJwks;
use Kipchak\Core\Components\App;

class JWKS implements Interfaces\Middleware
{
    public static function initialise(App $app): void
    {
        $container = $app->getContainer();
        if (!empty(Config::get('kipchak.auth.jwks'))) {
            $auth = Config::get('kipchak.auth.jwks');
            if ($auth['enabled']) {
                // Enable JWKS globally
                $app->add(new AuthJWKS($container));
            }
        }

    }

}