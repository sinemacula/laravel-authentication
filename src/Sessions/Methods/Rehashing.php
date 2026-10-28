<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Methods;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;

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
 * guard's attempt is open, a save of the user it validated is taken for the
 * rehash only when the hash before the save and the hash saved both verify the
 * password the attempt was made with: any other save, by a callback or by any
 * code before the attempt ends, changes the password. A validation outside an
 * attempt (`validate()`, as a "confirm your password" step does before a
 * change) marks nothing, and no other user is ever marked. Users are told apart
 * as `AccountAttempts::account()` tells accounts apart, so the same key in
 * another database is another user.
 *
 * A guard's attempts are kept innermost last, since an `attemptWhen()` callback
 * may make another attempt on the same guard: an attempt's end closes the
 * innermost open attempt that validated its user (or none), and leaves the
 * attempt around it open for its own rehash. An attempt that threw never ends,
 * so a new attempt of the guard first closes those innermost that cannot be
 * running around it: one that validated no one, was made without a password, or
 * already held a save as its rehash.
 *
 * The forced rehash of `logoutOtherDevices()` saves the same password too, so a
 * save taken for an attempt's rehash is held rather than dropped:
 * `OtherDeviceLogout`, which follows the forced save, runs it, and the end of
 * the attempt drops it. One save is held per user, the latest.
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
    /** @var list<string> The users the package's own running rehashes are for, innermost last. */
    private array $rehashing = [];

    /** @var array<string, list<array{password: \SensitiveParameterValue, user: ?string, held: ?\Closure(): void}>> Per guard, its credential attempts that have started and not ended, innermost last: the password each was made with, the user it validated, and the change it holds as its rehash. */
    private array $attempts = [];

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
        $attempts = $this->attempts[$guard] ?? [];

        while ($attempts !== [] && !self::mayEnclose($attempts[array_key_last($attempts)])) {
            array_pop($attempts);
        }

        $attempts[] = ['password' => new \SensitiveParameterValue($credentials['password'] ?? null), 'user' => null, 'held' => null];

        $this->attempts[$guard] = $attempts;
    }

    /**
     * Record that the guard validated the user's credentials, which marks the
     * user only for the guard's innermost attempt, and only when that attempt
     * has validated no one yet.
     *
     * @param  string  $guard
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function validated(string $guard, Authenticatable $user): void
    {
        $attempts = $this->attempts[$guard] ?? [];
        $index    = array_key_last($attempts);

        if ($index === null || $attempts[$index]['user'] !== null) {
            return;
        }

        $attempts[$index]['user'] = self::key($user);

        $this->attempts[$guard] = $attempts;
    }

    /**
     * Record that an attempt of the guard ended for the user (`null` when it
     * found no one), which closes the innermost of the guard's attempts that
     * validated that user or no one, and drops the change it held: that was its
     * rehash.
     *
     * @param  string  $guard
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function ended(string $guard, ?Authenticatable $user): void
    {
        $key      = $user === null ? null : self::key($user);
        $attempts = $this->attempts[$guard] ?? [];

        foreach (array_reverse($attempts, true) as $index => $attempt) {

            if ($attempt['user'] !== null && $attempt['user'] !== $key) {
                continue;
            }

            array_splice($attempts, $index, 1);

            $this->attempts[$guard] = $attempts;

            return;
        }
    }

    /**
     * Run the change of the user's password unless it is an automatic rehash.
     * The package's own rehash drops it. A save an open attempt may have made
     * as its rehash (the attempt validated this user, and was made with the
     * password both the previous and the saved hash verify) is held until
     * `forced()` runs it or the attempt's end drops it. Anything else runs at
     * once.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $previous
     * @param  \Closure(): void  $change
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function unlessRehash(Authenticatable $user, mixed $previous, \Closure $change): void
    {
        $key = self::key($user);

        if (in_array($key, $this->rehashing, true)) {
            return;
        }

        $attempt = $this->rehashingAttempt($key, $user, $previous);

        if ($attempt !== null) {

            $this->release($key);

            [$guard, $index] = $attempt;

            $this->attempts[$guard][$index]['held'] = $change;

            return;
        }

        $change();
    }

    /**
     * Record that a guard forced a rehash of the user's password to sign its
     * other devices out (`OtherDeviceLogout`), which runs the change held for
     * that user: the forced save, not an attempt's rehash.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function forced(Authenticatable $user): void
    {
        $change = $this->release(self::key($user));

        if ($change === null) {
            return;
        }

        $change();
    }

    /**
     * The guard and position of the innermost open attempt that validated the
     * user and was made with the password both the user's previous and saved
     * hash verify, if any.
     *
     * @param  string  $key
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $previous
     * @return ?array{0: string, 1: int}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function rehashingAttempt(string $key, Authenticatable $user, mixed $previous): ?array
    {
        foreach ($this->attempts as $guard => $attempts) {
            foreach (array_reverse($attempts, true) as $index => $attempt) {
                $password = $attempt['password']->getValue();

                if ($attempt['user'] === $key && self::verifies($password, $user->getAuthPassword()) && self::verifies($password, $previous)) {
                    return [$guard, $index];
                }
            }
        }

        return null;
    }

    /**
     * Stop holding the change of the user's password, returning it, if any.
     *
     * @param  string  $key
     * @return ?\Closure(): void
     */
    private function release(string $key): ?\Closure
    {
        foreach ($this->attempts as $guard => $attempts) {
            foreach ($attempts as $index => $attempt) {
                if ($attempt['user'] === $key && $attempt['held'] !== null) {

                    $this->attempts[$guard][$index]['held'] = null;

                    return $attempt['held'];
                }
            }
        }

        return null;
    }

    /**
     * Whether an attempt left open could still be running around a new attempt
     * of its guard: it validated a user, was made with a password, and holds no
     * save as its rehash yet.
     *
     * @param  array{password: \SensitiveParameterValue, user: ?string, held: ?\Closure(): void}  $attempt
     * @return bool
     */
    private static function mayEnclose(array $attempt): bool
    {
        return $attempt['user'] !== null && $attempt['held'] === null && is_string($attempt['password']->getValue());
    }

    /**
     * Whether the hash verifies the password. A hash the application's hasher
     * refuses to check, such as one of another algorithm under the hasher's
     * `verify` option, verifies nothing, so the change is answered as one.
     *
     * @param  mixed  $password
     * @param  mixed  $hash
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function verifies(#[\SensitiveParameter] mixed $password, mixed $hash): bool
    {
        if (!is_string($password)) {
            return false;
        }

        try {
            return Container::getInstance()->make(Hasher::class)->check($password, $hash);
        } catch (\RuntimeException) {
            return false;
        }
    }

    /**
     * What tells users apart: for an identity, the account
     * `AccountAttempts::account()` names (for an Eloquent model, the row it is
     * stored in); for any other user, its class and auth identifier.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return string
     */
    private static function key(Authenticatable $user): string
    {
        return $user instanceof Identity ? AccountAttempts::account($user) : implode("\0", [$user::class, IdentifierCoercion::stringify($user->getAuthIdentifier())]);
    }
}
