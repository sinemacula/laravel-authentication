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
 * being upgraded from the password itself being changed. A save is a rehash
 * only as a user provider makes one: the previous hash needed rehashing, and
 * both it and the saved hash verify the password signed in with.
 *
 * Two rehashes are marked. The package's own marks its identity and password
 * inside `during()`, and the mark is cleared in `finally`, so an exception
 * never leaves it set. Laravel's own guards (`SessionGuard::attempt()`,
 * `attemptWhen()` and `once()`) rehash through their user provider at a point
 * no event marks: after `Validated` and after `attemptWhen()`'s callbacks,
 * before the attempt ends (`Login`, `Authenticated` or `Failed`), and they save
 * the very model instance the attempt validated. So while a guard's attempt is
 * open, a save is taken for its rehash only when it saves that instance, still
 * standing for the user validated, and re-encodes the password the attempt was
 * made with. Any other save of the user changes the password, and once a change
 * of the user's password has run, no save is taken for the rehash of an attempt
 * open for that user: a change back to the attempt's password, through any
 * instance, is a change too. A validation outside an attempt (`validate()`, as
 * a "confirm your password" step does before a change) marks nothing.
 *
 * A guard's attempts are kept innermost last, since an `attemptWhen()` callback
 * may make another attempt on the same guard. An attempt ends with the event
 * that carries the instance it validated, or, having validated no one, with the
 * guard's next end, so an event for another instance (a nested attempt's, or a
 * session or remember-me user resolved inside a callback) leaves it open. An
 * attempt that threw never ends, so a new attempt of the guard first lets go of
 * every attempt that cannot be running around it (one whose instance is gone or
 * whose user's password changed, or that validated no one or was made without a
 * password), and an attempt that validates an instance lets go of the guard's
 * earlier attempts for that instance, so a guard keeps at most one attempt per
 * instance still held. Two cases end an attempt early, so its own rehash then
 * revokes: an `Auth::login()` of the very instance it validated inside its
 * callback, and an attempt inside its callback that validates that same
 * instance (from a provider that caches its users) and is refused.
 *
 * The forced rehash of `logoutOtherDevices()` re-encodes the same password, so
 * a save taken for an attempt's rehash is held rather than dropped, one per
 * user (the latest), apart from the attempts, since the save's other listeners
 * may end or make attempts before `OtherDeviceLogout`. That event, which
 * follows the forced save, runs it; a new attempt that finds no open attempt
 * for the instance saved drops it, as the rehash of an attempt that ended. A
 * change of the user's password leaves it held, since that change may yet be
 * rolled back, so a sign-out after it may revoke twice. Users are told apart as
 * `AccountAttempts::account()` tells accounts apart, so the same key in another
 * database is another user.
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
    /** @var list<array{user: string, password: \SensitiveParameterValue}> The package's own running rehashes, innermost last: the user each is for and the password it re-encodes. */
    private array $rehashing = [];

    /** @var array<string, list<array{password: \SensitiveParameterValue, user: ?string, instance: ?\WeakReference<\Illuminate\Contracts\Auth\Authenticatable>, spent: bool}>> Per guard, its credential attempts that have started and not ended, innermost last: the password each was made with, the user and the instance it validated, and whether a change of that user's password has run since. */
    private array $attempts = [];

    /** @var array<string, \Closure(): void> Per user, the latest change taken for an open attempt's rehash. */
    private array $held = [];

    /** @var array<string, \Illuminate\Contracts\Auth\Authenticatable> Per user, the instance the change held for the user saved. */
    private array $heldFor = [];

    /**
     * Run the callback marked as the automatic rehash of the user's password
     * with the password.
     *
     * @template TReturn
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $password
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @param-immediately-invoked-callable $callback
     */
    public function during(Authenticatable $user, #[\SensitiveParameter] mixed $password, \Closure $callback): mixed
    {
        $this->rehashing[] = ['user' => self::key($user), 'password' => new \SensitiveParameterValue($password)];

        try {
            return $callback();
        } finally {
            array_pop($this->rehashing);
        }
    }

    /**
     * Record that the guard started a credential attempt with the credentials,
     * letting go of the guard's attempts that cannot be running around it and
     * of the saves held for instances no open attempt validated.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $credentials
     * @return void
     */
    public function attempting(string $guard, #[\SensitiveParameter] array $credentials): void
    {
        $attempts = array_values(array_filter($this->attempts[$guard] ?? [], static fn (array $attempt): bool => self::mayEnclose($attempt)));

        $attempts[] = ['password' => new \SensitiveParameterValue($credentials['password'] ?? null), 'user' => null, 'instance' => null, 'spent' => false];

        $this->attempts[$guard] = $attempts;

        $this->dropHeldOutsideAttempts();
    }

    /**
     * Record that the guard validated the user's credentials, which marks the
     * instance only for the guard's innermost attempt, and only when that
     * attempt has validated no one yet. An earlier attempt of the guard that
     * validated the same instance is let go of.
     *
     * @param  string  $guard
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function validated(string $guard, Authenticatable $user): void
    {
        $attempts  = $this->attempts[$guard] ?? [];
        $innermost = $attempts === [] ? null : $attempts[count($attempts) - 1];

        if ($innermost === null || $innermost['user'] !== null) {
            return;
        }

        $instance = \WeakReference::create($user);
        $attempts = array_values(array_filter(array_slice($attempts, 0, -1), static fn (array $attempt): bool => $attempt['instance'] !== $instance));

        $attempts[] = ['user' => self::key($user), 'instance' => $instance] + $innermost;

        $this->attempts[$guard] = $attempts;
    }

    /**
     * Record that an attempt of the guard ended for the user (`null` when it
     * found no one), which closes the innermost of the guard's attempts that
     * validated that very instance or no one.
     *
     * @param  string  $guard
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function ended(string $guard, ?Authenticatable $user): void
    {
        $attempts = $this->attempts[$guard] ?? [];

        foreach (array_reverse($attempts, true) as $index => $attempt) {

            if ($attempt['user'] !== null && ($user === null || $attempt['instance'] !== \WeakReference::create($user))) {
                continue;
            }

            array_splice($attempts, $index, 1);

            $this->attempts[$guard] = $attempts;

            return;
        }
    }

    /**
     * Run the change of the user's password unless it is an automatic rehash. A
     * save the package's own rehash of the user makes, with its password, is
     * dropped. A save an open attempt may have made as its rehash (the attempt
     * validated this very instance of this user, no change of the user's
     * password has run since, and the attempt was made with its password) is
     * held, in place of any change held for the user, until `forced()` runs it,
     * or a new attempt finds no open attempt for the instance it saved. Either
     * is a rehash only when the previous hash needed one and both it and the
     * saved hash verify that password. Anything else runs at once, and from
     * then on no attempt open for the user takes a save for its rehash.
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

        if ($this->isPackageRehash($key, $user, $previous)) {
            return;
        }

        if ($this->isAttemptRehash($key, $user, $previous)) {

            $this->held[$key]    = $change;
            $this->heldFor[$key] = $user;

            return;
        }

        $this->changed($key);

        $change();
    }

    /**
     * Record that a guard forced a rehash of the user's password to sign its
     * other devices out (`OtherDeviceLogout`), which runs the change held for
     * that user: the forced save, not an attempt's rehash, so a change like any
     * other.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function forced(Authenticatable $user): void
    {
        $key = self::key($user);

        if (!isset($this->held[$key])) {
            return;
        }

        $change = $this->held[$key];

        unset($this->held[$key], $this->heldFor[$key]);

        $this->changed($key);

        $change();
    }

    /**
     * Drop the changes held for instances no open attempt validated: such a
     * save was an ended attempt's rehash, since `OtherDeviceLogout` would have
     * followed a forced one before any new attempt.
     *
     * @return void
     */
    private function dropHeldOutsideAttempts(): void
    {
        $open = array_column(array_merge(...array_values($this->attempts)), 'instance');

        foreach ($this->heldFor as $key => $instance) {

            if (in_array(\WeakReference::create($instance), $open, true)) {
                continue;
            }

            unset($this->held[$key], $this->heldFor[$key]);
        }
    }

    /**
     * Whether the package's own running rehash of the user re-encodes the
     * password it was given.
     *
     * @param  string  $key
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $previous
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isPackageRehash(string $key, Authenticatable $user, mixed $previous): bool
    {
        foreach ($this->rehashing as $rehash) {
            if ($rehash['user'] === $key && self::isRehashOf($rehash['password']->getValue(), $user->getAuthPassword(), $previous)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether an open attempt validated this very instance of this user, no
     * change of the user's password has run since, and the save re-encodes the
     * password the attempt was made with.
     *
     * @param  string  $key
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $previous
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isAttemptRehash(string $key, Authenticatable $user, mixed $previous): bool
    {
        foreach ($this->attempts as $attempts) {
            foreach ($attempts as $attempt) {
                if (self::isOpenFor($attempt, $key, $user) && self::isRehashOf($attempt['password']->getValue(), $user->getAuthPassword(), $previous)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Record that a change of the user's password ran, so no attempt open for
     * the user takes a save for its rehash any more. A change held for the user
     * stays held: this one may yet be rolled back.
     *
     * @param  string  $key
     * @return void
     */
    private function changed(string $key): void
    {
        foreach ($this->attempts as $guard => $attempts) {
            $this->attempts[$guard] = array_map(static fn (array $attempt): array => $attempt['user'] === $key ? ['spent' => true] + $attempt : $attempt, $attempts);
        }
    }

    /**
     * Whether an attempt left open could still be running around a new attempt
     * of its guard and take a save for its rehash: the instance it validated is
     * still held somewhere, no change of its user's password has run since, and
     * it was made with a password.
     *
     * @param  array{password: \SensitiveParameterValue, user: ?string, instance: ?\WeakReference<\Illuminate\Contracts\Auth\Authenticatable>, spent: bool}  $attempt
     * @return bool
     */
    private static function mayEnclose(array $attempt): bool
    {
        return $attempt['instance']?->get() !== null && !$attempt['spent'] && is_string($attempt['password']->getValue());
    }

    /**
     * Whether the attempt validated this very instance of this user, and no
     * change of the user's password has run since.
     *
     * @param  array{password: \SensitiveParameterValue, user: ?string, instance: ?\WeakReference<\Illuminate\Contracts\Auth\Authenticatable>, spent: bool}  $attempt
     * @param  string  $key
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return bool
     */
    private static function isOpenFor(array $attempt, string $key, Authenticatable $user): bool
    {
        return $attempt['user'] === $key && $attempt['instance'] === \WeakReference::create($user) && !$attempt['spent'];
    }

    /**
     * Whether a save of the saved hash over the previous one is a rehash of the
     * password, as a user provider makes it: both hashes verify the password,
     * and the previous one needed rehashing.
     *
     * @param  mixed  $password
     * @param  mixed  $saved
     * @param  mixed  $previous
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function isRehashOf(#[\SensitiveParameter] mixed $password, mixed $saved, mixed $previous): bool
    {
        return self::verifies($password, $saved) && self::verifies($password, $previous) && Container::getInstance()->make(Hasher::class)->needsRehash($previous);
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
