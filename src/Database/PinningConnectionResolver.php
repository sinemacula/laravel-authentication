<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;

/**
 * Connection resolver that hands each connection Eloquent resolves through it
 * to a callback before returning it.
 *
 * `WriteConnection::during()` installs it as the model connection resolver for
 * the length of its callback, so every model read inside, on whichever
 * connection the model lives (a tenant in a separate landlord database, say),
 * can be pinned to that connection's write PDO.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PinningConnectionResolver implements ConnectionResolverInterface
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $resolver
     * @param  \Closure(\Illuminate\Database\Connection): void  $pin
     */
    public function __construct(

        /** The resolver whose connections are handed out. */
        private ConnectionResolverInterface $resolver,

        /** Callback that pins a connection's reads to its write PDO. */
        private \Closure $pin,
    ) {}

    /**
     * Resolve the connection through the wrapped resolver and pin it.
     *
     * @param  string|\UnitEnum|null  $name
     * @return \Illuminate\Database\ConnectionInterface
     */
    #[\Override]
    public function connection($name = null): ConnectionInterface
    {
        $connection = $this->resolver->connection($name);

        if ($connection instanceof Connection) {
            ($this->pin)($connection);
        }

        return $connection;
    }

    /**
     * Return the wrapped resolver's default connection name.
     *
     * @return string
     */
    #[\Override]
    public function getDefaultConnection(): string
    {
        return $this->resolver->getDefaultConnection();
    }

    /**
     * Set the wrapped resolver's default connection name.
     *
     * @param  string|\UnitEnum  $name
     * @return void
     */
    #[\Override]
    public function setDefaultConnection($name): void
    {
        $this->resolver->setDefaultConnection($name);
    }
}
