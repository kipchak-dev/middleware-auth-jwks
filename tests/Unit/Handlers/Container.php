<?php

namespace Kipchak\Middleware\Auth\JWKS\Tests\Unit\Handlers;

use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;

final class Container implements ContainerInterface
{
    public array $entries = [];

    public function set(string $id, mixed $value): void
    {
        $this->entries[$id] = $value;
    }

    public function get(string $id): mixed
    {
        if (!array_key_exists($id, $this->entries)) {
            throw new class ("No entry {$id}") extends \RuntimeException implements NotFoundExceptionInterface {
            };
        }
        $entry = $this->entries[$id];

        return $entry instanceof \Closure ? $entry($this) : $entry;
    }

    public function has(string $id): bool
    {
        return array_key_exists($id, $this->entries);
    }
}
