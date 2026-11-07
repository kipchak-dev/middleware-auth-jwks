<?php

namespace Kipchak\Middleware\Auth\JWKS\Exceptions;

/**
 * The key set could not be fetched, or the document fetched is not a key set. Nothing is cached.
 */
final class KeySetUnavailableException extends \RuntimeException
{
}
