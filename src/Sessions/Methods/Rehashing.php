<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Methods;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;

/**
 * Marks the automatic rehash of a password on sign-in, so a listener that ends
 * an identity's sessions when its password changes can tell the stored hash
 * being upgraded from the password itself being changed.
 *
 * Two rehashes are marked. The package's own runs inside `during()`, and the
 * mark is cleared in `finally`, so an exception never leaves it set. Laravel's
 * own guards (`SessionGuard::attempt()`, `attemptWhen()` and `once()`) rehash
 * through their user provider between validating the credentials of an attempt
 * and ending it, so the user a guard validated during an attempt is marked from
 * `Validated` until that guard's attempt ends (`Login`, `Authenticated` or
 * `Failed`). A validation outside an attempt (`validate()`, as a "confirm your
 * password" step does before a change) marks nothing, and no other user is ever
 * marked.
 *
 * One instance is shared through the container, scoped, so whatever an attempt
 * that never ended left behind is gone for the next request or job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Rehashing
{
    /** @var int How many rehashes are running, so a nested one does not clear the mark early. */
    private int $depth = 0;

    /** @var array<string, bool> Per guard, whether its credential attempt has started and not ended. */
    private array $attempts = [];

    /** @var array<string, array{0: class-string, 1: ?string}> Per guard, the user whose credentials its running attempt validated. */
    private array $validated = [];

    /**
     * Run the callback marked as an automatic rehash.
     *
     * @template TReturn
     *
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @param-immediately-invoked-callable $callback
     */
    public function during(\Closure $callback): mixed
    {
        $this->depth++;

        try {
            return $callback();
        } finally {
            $this->depth--;
        }
    }

    /**
     * Record that the guard started a credential attempt.
     *
     * @param  string  $guard
     * @return void
     */
    public function attempting(string $guard): void
    {
        $this->attempts[$guard] = true;

        unset($this->validated[$guard]);
    }

    /**
     * Record that the guard validated the user's credentials, which marks the
     * user only during an attempt of that guard.
     *
     * @param  string  $guard
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function validated(string $guard, Authenticatable $user): void
    {
        if (!($this->attempts[$guard] ?? false)) {
            return;
        }

        $this->validated[$guard] = self::key($user);
    }

    /**
     * Record that the guard's attempt ended, which clears its mark.
     *
     * @param  string  $guard
     * @return void
     */
    public function ended(string $guard): void
    {
        unset($this->attempts[$guard], $this->validated[$guard]);
    }

    /**
     * Whether the package's automatic rehash is running.
     *
     * @return bool
     */
    public function isRunning(): bool
    {
        return $this->depth > 0;
    }

    /**
     * Whether a change to the user's password may be an automatic rehash: the
     * package's own is running, or a guard's attempt validated this user and
     * has not ended.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return bool
     */
    public function isRunningFor(Authenticatable $user): bool
    {
        return $this->isRunning() || in_array(self::key($user), $this->validated, true);
    }

    /**
     * What tells users apart: their class and auth identifier.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return array{0: class-string, 1: ?string}
     */
    private static function key(Authenticatable $user): array
    {
        return [$user::class, IdentifierCoercion::stringify($user->getAuthIdentifier())];
    }
}
