<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Methods;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;

/**
 * Marks the automatic rehash of a password on sign-in, so a listener that ends
 * an identity's sessions when its password changes can tell the stored hash
 * being upgraded from the password itself being changed.
 *
 * Two rehashes are marked. The package's own marks its identity inside
 * `during()`, and the mark is cleared in `finally`, so an exception never
 * leaves it set. Laravel's own guards (`SessionGuard::attempt()`,
 * `attemptWhen()` and `once()`) rehash through their user provider at a point
 * no event marks: after `Validated` and after `attemptWhen()`'s callbacks,
 * before the attempt ends (`Login`, `Authenticated` or `Failed`). So while a
 * guard's attempt is open, a change to the user it validated is taken for the
 * rehash only when the stored hash still verifies the password the attempt was
 * made with: a callback, or any other code before the attempt ends, that saves
 * another password changes it. A validation outside an attempt (`validate()`,
 * as a "confirm your password" step does before a change) marks nothing, and no
 * other user is ever marked.
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
    /** @var list<array{0: class-string, 1: ?string}> The users the package's own running rehashes are for, innermost last. */
    private array $rehashing = [];

    /** @var array<string, \SensitiveParameterValue> Per guard, the password of its credential attempt that has started and not ended. */
    private array $attempts = [];

    /** @var array<string, array{0: class-string, 1: ?string}> Per guard, the user whose credentials its running attempt validated. */
    private array $validated = [];

    /**
     * Run the callback marked as the automatic rehash of the user's password.
     *
     * @template TReturn
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @param-immediately-invoked-callable $callback
     */
    public function during(Authenticatable $user, \Closure $callback): mixed
    {
        $this->rehashing[] = self::key($user);

        try {
            return $callback();
        } finally {
            array_pop($this->rehashing);
        }
    }

    /**
     * Record that the guard started a credential attempt with the credentials.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $credentials
     * @return void
     */
    public function attempting(string $guard, #[\SensitiveParameter] array $credentials): void
    {
        $this->attempts[$guard] = new \SensitiveParameterValue($credentials['password'] ?? null);

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
        if (!isset($this->attempts[$guard])) {
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
     * Whether a change to the user's password is an automatic rehash: the
     * package's own is running for the user, or a guard's attempt validated
     * this user, has not ended, and was made with the password the user's
     * stored hash verifies.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function isRunningFor(Authenticatable $user): bool
    {
        $key = self::key($user);

        if (in_array($key, $this->rehashing, true)) {
            return true;
        }

        foreach (array_keys($this->validated, $key, true) as $guard) {
            if (self::verifies($this->attempts[$guard]->getValue(), $user)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the user's stored hash verifies the password. A hash the
     * application's hasher refuses to check, such as one of another algorithm
     * under the hasher's `verify` option, verifies nothing, so the change is
     * answered as one.
     *
     * @param  mixed  $password
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function verifies(#[\SensitiveParameter] mixed $password, Authenticatable $user): bool
    {
        if (!is_string($password)) {
            return false;
        }

        try {
            return Container::getInstance()->make(Hasher::class)->check($password, $user->getAuthPassword());
        } catch (\RuntimeException) {
            return false;
        }
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
