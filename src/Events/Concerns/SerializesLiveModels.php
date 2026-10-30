<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events\Concerns;

use Illuminate\Contracts\Database\ModelIdentifier;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Lets the live models of an event (its identity, principal, tenant and device)
 * cross a queue without being able to stop it from coming back.
 *
 * A live model that is an Eloquent model is stored as Laravel's model
 * identifier and fetched again from the writer when the event is restored, with
 * the relations it had loaded, or comes back `null` when its row no longer
 * exists; a database error still throws. A live part that is not an Eloquent
 * model is not serialised at all and comes back `null`, so no arbitrary object
 * enters the payload. Every other property crosses as it is.
 *
 * Expects the using class to declare every property it has: the restore
 * initialises them from the using class's scope, which is the only scope PHP
 * 8.3 lets initialise a readonly property.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait SerializesLiveModels
{
    /**
     * Prepare the object for serialization: each live model as its model
     * identifier, or `null`, and the other properties as they are.
     *
     * @return array<string, mixed>
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        return array_map(static fn (mixed $value): mixed => self::isLive($value) ? self::identify($value) : $value, get_object_vars($this));
    }

    /**
     * Restore the object after serialization, fetching each live model again.
     *
     * @param  array<string, mixed>  $values
     * @return void
     *
     * @SuppressWarnings("php:S100")
     */
    public function __unserialize(array $values): void
    {
        foreach ($values as $name => $value) {
            $this->{$name} = $value instanceof ModelIdentifier ? self::restore($value) : $value;
        }
    }

    /**
     * Whether the value is a live part of the event.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isLive(mixed $value): bool
    {
        return $value instanceof Identity || $value instanceof Principal || $value instanceof Tenant || $value instanceof Device;
    }

    /**
     * The identifier a live model crosses a queue as, or `null` for a part that
     * is not an Eloquent model.
     *
     * @param  object  $part
     * @return ?\Illuminate\Contracts\Database\ModelIdentifier
     */
    private static function identify(object $part): ?ModelIdentifier
    {
        return $part instanceof Model
            ? new ModelIdentifier($part::class, $part->getQueueableId(), $part->getQueueableRelations(), $part->getQueueableConnection())
            : null;
    }

    /**
     * The model an identifier names, read from the writer with its relations,
     * or `null` when its row no longer exists.
     *
     * @param  \Illuminate\Contracts\Database\ModelIdentifier  $identifier
     * @return ?\Illuminate\Database\Eloquent\Model
     */
    private static function restore(ModelIdentifier $identifier): ?Model
    {
        /** @var class-string<\Illuminate\Database\Eloquent\Model> $class */
        $class = $identifier->getClass();

        return (new $class)->setConnection($identifier->connection)
            ->newQueryForRestoration($identifier->id)
            ->useWritePdo()
            ->first()
            ?->loadMissing($identifier->relations);
    }
}
