<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Providers;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use SensitiveParameter;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use Stringable;

/**
 * Eloquent-backed identity provider.
 *
 * Implements `IdentityProvider` (which extends Laravel's `UserProvider`)
 * with the same surface as Laravel's first-party `EloquentUserProvider`,
 * minus the remember-me token methods which this stateless package
 * leaves inert.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
class ModelProvider implements IdentityProvider
{
    public function __construct(

        /** Hasher used to verify and optionally re-hash passwords. */
        protected Hasher $hasher,

        /**
         * Fully-qualified Eloquent model class name to authenticate against.
         *
         * @var class-string<\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable>
         */
        protected string $model,

    ) {}

    /**
     * Retrieve a user by its unique identifier.
     *
     * @param  mixed $identifier The stable identifier to look up.
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier): ?Authenticatable
    {
        $model = $this->createModel();

        // @phpstan-ignore staticMethod.dynamicCall (Eloquent newQuery is a real instance method; the strict rule misfires because of __callStatic)
        $query = $model->newQuery();

        /** @var (\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable)|null $result */
        $result = $query
            ->where($model->getAuthIdentifierName(), $identifier)
            ->first();

        return $result;
    }

    /**
     * Retrieve a user by its remember-me token.
     *
     * Stateless package: remember-me tokens are not supported.
     *
     * @param  mixed  $identifier The stable identifier.
     * @param  string $token      The remember-me token.
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByToken($identifier, #[SensitiveParameter] $token): ?Authenticatable
    {
        return null;
    }

    /**
     * Update the remember-me token for the given user.
     *
     * Stateless package: no-op.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user  The authenticated user.
     * @param  string                                    $token The new remember-me token.
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, #[SensitiveParameter] $token): void
    {
        // Intentionally empty: stateless package.
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * Password credentials are stripped before query composition so
     * the hasher remains the single source of password verification.
     *
     * @param  array<array-key, mixed> $credentials The credentials to match on.
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(#[SensitiveParameter] array $credentials): ?Authenticatable
    {
        $credentials = array_filter(
            $credentials,
            static fn (string $key): bool => ! str_contains($key, 'password'),
            ARRAY_FILTER_USE_KEY,
        );

        if ($credentials === []) {
            return null;
        }

        // @phpstan-ignore staticMethod.dynamicCall (Eloquent newQuery is a real instance method; the strict rule misfires because of __callStatic)
        $query = $this->createModel()->newQuery();

        foreach ($credentials as $key => $value) {

            if (is_array($value) || $value instanceof Stringable || is_string($value) || is_int($value)) {
                $query->where($key, $value);
                continue;
            }

            if ($value instanceof Closure) {
                $value($query);
            }
        }

        /** @var (\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable)|null $result */
        $result = $query->first();

        return $result;
    }

    /**
     * Validate the supplied credentials against the resolved user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user        The user to validate against.
     * @param  array<array-key, mixed>                       $credentials The credentials to validate.
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, #[SensitiveParameter] array $credentials): bool
    {
        $plain = $credentials['password'] ?? null;

        if (! is_string($plain) || $plain === '') {
            return false;
        }

        return $this->hasher->check($plain, $user->getAuthPassword());
    }

    /**
     * Rehash the user's password when the current hash is outdated.
     *
     * No-ops when no password is supplied, the supplied password is
     * not a string, or the user is not an Eloquent model.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user        The user whose password may need rehashing.
     * @param  array<array-key, mixed>                       $credentials The credentials submitted for authentication.
     * @param  bool                                       $force       Force a rehash regardless of hasher state.
     * @return void
     */
    public function rehashPasswordIfRequired(Authenticatable $user, #[SensitiveParameter] array $credentials, bool $force = false): void
    {
        $plain = $credentials['password'] ?? null;

        if (! is_string($plain) || $plain === '') {
            return;
        }

        if (! $user instanceof Model) {
            return;
        }

        if (! $force && ! $this->hasher->needsRehash($user->getAuthPassword())) {
            return;
        }

        // @phpstan-ignore staticMethod.dynamicCall, staticMethod.dynamicCall (Eloquent forceFill/save are real instance methods; strict rule misfires because of __callStatic)
        $user->forceFill([
            $user->getAuthPasswordName() => $this->hasher->make($plain),
        ])->save();
    }

    /**
     * Instantiate a fresh copy of the configured Eloquent model.
     *
     * The configured class must be both an Eloquent `Model` and an
     * `Authenticatable` so the provider can call `getAuthIdentifierName`,
     * `getAuthPassword`, etc. on the returned instance.
     *
     * @return \Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable
     */
    protected function createModel(): Model&Authenticatable
    {
        $class = '\\' . ltrim($this->model, '\\');

        /** @var \Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $model */
        $model = new $class();

        return $model;
    }
}
