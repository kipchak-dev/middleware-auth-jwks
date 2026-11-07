<?php

namespace Kipchak\Middleware\Auth\JWKS\Exceptions;

/**
 * The configuration would let the middleware accept tokens it should refuse, so it does not run.
 */
final class ConfigurationException extends \RuntimeException
{
}
