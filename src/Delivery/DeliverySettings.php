<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Delivery;

use Illuminate\Contracts\Config\Repository;

/**
 * The queue settings every delivery job the package queues is pushed with,
 * validated as they are read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeliverySettings
{
    /** @var string Prefix of every delivery setting's key. */
    public const string PREFIX = 'authentication.delivery.queue.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the settings are read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The queue connection a delivery job is pushed to, or `null` for the
     * application's default.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function queueConnection(): ?string
    {
        return $this->name('connection');
    }

    /**
     * The queue a delivery job is pushed to, or `null` for the connection's
     * default.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function queueName(): ?string
    {
        return $this->name('name');
    }

    /**
     * Whether the delivery connection uses Laravel's `sync` driver, which would
     * run a job during its dispatch.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function deliversSynchronously(): bool
    {
        return $this->driver($this->deliveryConnection()) === 'sync';
    }

    /**
     * Whether the delivery connection uses Laravel's `failover` driver and can
     * fall back to a `sync` connection.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function fallsBackToSync(): bool
    {
        $connection = $this->deliveryConnection();

        return $this->driver($connection) === 'failover' && $this->reachesSync($connection, []);
    }

    /**
     * Read every setting, failing closed on the first that is malformed.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function validate(): void
    {
        $this->queueName();
        $this->deliversSynchronously();
    }

    /**
     * The delivery connection, the configured one or the application's default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function deliveryConnection(): string
    {
        $connection = $this->queueConnection() ?? $this->config->get('queue.default');

        if (!is_string($connection) || !is_string($this->driver($connection))) {
            $message = sprintf('%sconnection must name a connection configured in `queue.connections`, or be null for `queue.default`.', self::PREFIX);

            throw new \InvalidArgumentException($message);
        }

        return $connection;
    }

    /**
     * The driver of the queue connection, or `null` when it is not configured.
     *
     * @param  string  $connection
     * @return ?string
     */
    private function driver(string $connection): ?string
    {
        $driver = $this->config->get("queue.connections.{$connection}.driver");

        return is_string($driver) ? $driver : null;
    }

    /**
     * Whether the connection is a `sync` one, or a `failover` one that reaches
     * one, following no connection twice.
     *
     * @param  string  $connection
     * @param  list<string>  $path
     * @return bool
     */
    private function reachesSync(string $connection, array $path): bool
    {
        $driver = $this->driver($connection);

        if ($driver !== 'failover' || in_array($connection, $path, true)) {
            return $driver === 'sync';
        }

        $listed = $this->config->get("queue.connections.{$connection}.connections");
        $path[] = $connection;

        foreach (is_array($listed) ? $listed : [] as $next) {
            if (is_string($next) && $this->reachesSync($next, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Read a queue setting, `null` when it is null or empty.
     *
     * @param  string  $key
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function name(string $key): ?string
    {
        $value = $this->config->get(self::PREFIX . $key);

        if ($value === null || $value === '') {
            return null;
        }

        if (!is_string($value)) {
            throw new \InvalidArgumentException(sprintf('%s%s must be a name, or null for the default.', self::PREFIX, $key));
        }

        return $value;
    }
}
