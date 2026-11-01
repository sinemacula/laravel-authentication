<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Exceptions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;

/**
 * Thrown when the configured session model does not satisfy the explicit
 * Eloquent-backed persistence boundary required by refresh and last-use flows,
 * or does not live on the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidSessionModelConfigurationException extends \RuntimeException
{
    /**
     * Validate that the class satisfies the Eloquent session boundary.
     *
     * @param  string  $class
     * @return void
     *
     * @throws static
     */
    public static function validate(string $class): void
    {
        if (!is_subclass_of($class, Model::class) || !is_subclass_of($class, EloquentSession::class)) {
            throw self::unsupported($class);
        }
    }

    /**
     * Build an exception for a session model that does not live on the storage
     * connection, naming both connections.
     *
     * @param  string  $configured
     * @param  string  $session
     * @param  string  $storage
     * @return self
     */
    public static function offStorage(string $configured, string $session, string $storage): self
    {
        $message = 'authentication.session.model [%s] must live on the storage connection (authentication.storage.connection),'
            . ' where the package writes its sessions with its other rows in one transaction: the session model is on [%s],'
            . ' the storage connection is [%s].';

        return new self(sprintf($message, $configured, $session, $storage));
    }

    /**
     * Build an exception for an unsupported session model.
     *
     * @param  string  $configured
     * @return self
     */
    public static function unsupported(string $configured): self
    {
        $display = $configured === '' ? '(empty string)' : $configured;

        return new self(
            sprintf(
                'authentication.session.model must be a non-empty class-string of an Eloquent model implementing [%s]; got [%s].',
                EloquentSession::class,
                $display,
            ),
        );
    }
}
