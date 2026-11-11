<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Methods;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Marks the automatic rehash of a password on sign-in, so a listener that ends
 * sessions on a password change can tell a rehash from a change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Rehashing
{
    /** @var list<array{user: string, password: \SensitiveParameterValue, spent: bool}> The package's own running rehashes, innermost last. */
    private array $rehashing = [];

    /** @var array<string, list<array{password: \SensitiveParameterValue, user: ?string, instance: ?\WeakReference<\Illuminate\Contracts\Auth\Authenticatable>, spent: bool}>> Per guard, its open credential attempts, innermost last. */
    private array $attempts = [];

    /** @var array<string, \Closure(): void> Per user, the latest change taken for a rehash, held for `OtherDeviceLogout`. */
    private array $held = [];

    /**
     * Run the callback marked as the automatic rehash of the user's password.
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
        $key    = self::key($user);
        $before = $this->held[$key] ?? null;

        $this->rehashing[] = ['user' => $key, 'password' => new \SensitiveParameterValue($password), 'spent' => false];

        try {
            return $callback();
        } finally {
            array_pop($this->rehashing);

            unset($this->held[$key]);

            if ($before !== null) {
                $this->held[$key] = $before;
            }
        }
    }

    /**
     * Record that the guard started a credential attempt with the credentials,
     * letting go of the guard's attempts that cannot be running around it.
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
    }

    /**
     * Record that the guard's innermost attempt validated the user's
     * credentials.
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
     * Record that an attempt of the guard ended for the user, or for no one.
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
     * Run the change of the user's password unless it is an automatic rehash,
     * which is held for `forced()` instead.
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

        if ($this->isPackageRehash($key, $user, $previous) || $this->isAttemptRehash($key, $user, $previous)) {

            $this->held[$key] = $change;

            return;
        }

        $this->changed($key);

        $change();
    }

    /**
     * Run the change held for the user once a guard forced a rehash of its
     * password (`OtherDeviceLogout`).
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function forced(Authenticatable $user): void
    {
        $key = self::key($user);

        $change = $this->held[$key] ?? null;

        if ($change === null) {
            return;
        }

        unset($this->held[$key]);

        $this->changed($key);

        $change();
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
            if ($rehash['user'] === $key && !$rehash['spent'] && self::isRehashOf($rehash['password']->getValue(), $user->getAuthPassword(), $previous)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether an open attempt validated this very instance and the save
     * re-encodes the password the attempt was made with.
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
     * Record that a change of the user's password ran, so no open attempt or
     * running rehash of the user takes a save for its rehash any more.
     *
     * @param  string  $key
     * @return void
     */
    private function changed(string $key): void
    {
        $this->rehashing = array_map(static fn (array $rehash): array => $rehash['user'] === $key ? ['spent' => true] + $rehash : $rehash, $this->rehashing);

        foreach ($this->attempts as $guard => $attempts) {
            $this->attempts[$guard] = array_map(static fn (array $attempt): array => $attempt['user'] === $key ? ['spent' => true] + $attempt : $attempt, $attempts);
        }
    }

    /**
     * Whether an attempt left open could still be running around a new attempt
     * of its guard.
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
     * Whether both the saved and the previous hash verify the password.
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
        return self::verifies($password, $saved) && self::verifies($password, $previous);
    }

    /**
     * Whether the hash verifies the password; one the hasher refuses to check
     * verifies nothing.
     *
     * @param  mixed  $password
     * @param  mixed  $hash
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function verifies(#[\SensitiveParameter] mixed $password, mixed $hash): bool
    {
        if (!is_string($password) || !is_string($hash)) {
            return false;
        }

        try {
            return Container::getInstance()->make(Hasher::class)->check($password, $hash);
        } catch (\RuntimeException) {
            return false;
        }
    }

    /**
     * What tells users apart.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return string
     */
    private static function key(Authenticatable $user): string
    {
        return $user instanceof Identity ? AccountAttempts::account($user) : implode("\0", [$user::class, IdentifierCoercion::stringify($user->getAuthIdentifier())]);
    }
}
