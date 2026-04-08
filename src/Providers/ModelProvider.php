<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Providers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;

/**
 * Eloquent-backed identity provider.
 *
 * Mirrors the surface of Laravel's `EloquentUserProvider` minus the
 * remember-me token methods, which are inert for this stateless
 * package. Non-`final` so consumers may subclass `createModel()` or
 * `retrieveByCredentials()` for tenant scoping, soft-delete
 * exclusion, or other domain-specific lookups.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class ModelProvider implements IdentityProvider
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @param  string  $model
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Hasher used to verify and optionally re-hash passwords. */
        protected Hasher $hasher,

        /**
         * Fully-qualified Eloquent model class name to authenticate
         * against.
         */
        protected string $model,

    ) {
        if ($model === '') {

            $message = 'ModelProvider requires a non-empty Eloquent model class -'
                . ' set `auth.providers.<name>.model` to a fully-qualified class'
                . ' name in config/auth.php.';

            throw new \InvalidArgumentException($message);
        }

        if (!class_exists($model)) {
            throw new \InvalidArgumentException(sprintf('ModelProvider received unknown class "%s" as its identity model.', $model));
        }

        if (!is_subclass_of($model, Model::class) || !is_subclass_of($model, Authenticatable::class)) {
            throw new \InvalidArgumentException(sprintf('ModelProvider model "%s" must be both an Eloquent Model and implement Authenticatable.', $model));
        }
    }

    /**
     * Retrieve a user by its unique identifier.
     *
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    #[\Override]
    public function retrieveById(mixed $identifier): ?Authenticatable
    {
        $model = $this->createModel();

        $user = $this->freshQuery($model)
            ->where($model->getAuthIdentifierName(), $identifier)
            ->first();

        assert($user === null || $user instanceof Authenticatable);

        return $user;
    }

    /**
     * Inert in this stateless package: returns `null`. Implemented
     * only to satisfy `UserProvider`.
     *
     * @param  mixed  $identifier
     * @param  mixed  $token
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    #[\Override]
    public function retrieveByToken(mixed $identifier, #[\SensitiveParameter] mixed $token): ?Authenticatable
    {
        return null;
    }

    /**
     * Inert in this stateless package: empty no-op. Implemented only
     * to satisfy `UserProvider`.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $token
     * @return void
     */
    #[\Override]
    public function updateRememberToken(Authenticatable $user, #[\SensitiveParameter] mixed $token): void
    {
        // Intentionally empty: stateless package.
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * Password keys are stripped before query composition so the
     * hasher stays the single source of password verification. An
     * empty filtered set returns `null` rather than running a
     * where-less query, which would otherwise return the first row
     * in the table - a surprising and unsafe authentication.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    #[\Override]
    public function retrieveByCredentials(#[\SensitiveParameter] array $credentials): ?Authenticatable
    {
        $filtered = $this->filterCredentialKeys($credentials);

        if ($filtered === []) {
            return null;
        }

        $query = $this->freshQuery($this->createModel());

        if (!$this->applyCredentialClauses($query, $filtered)) {
            return null;
        }

        $user = $query->first();

        assert($user === null || $user instanceof Authenticatable);

        return $user;
    }

    /**
     * Validate the supplied credentials against the resolved user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    #[\Override]
    public function validateCredentials(Authenticatable $user, #[\SensitiveParameter] array $credentials): bool
    {
        $plain = $credentials['password'] ?? null;

        if (!is_string($plain) || $plain === '') {
            return false;
        }

        return $this->hasher->check($plain, $user->getAuthPassword());
    }

    /**
     * Rehash the user's password when the current hash is outdated.
     * No-ops when no password is supplied or the user is not an
     * Eloquent model.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<array-key, mixed>  $credentials
     * @param  bool  $force
     * @return void
     */
    #[\Override]
    public function rehashPasswordIfRequired(
        Authenticatable $user,
        #[\SensitiveParameter] array $credentials,
        bool $force = false,
    ): void {
        $plain = $credentials['password'] ?? null;

        if (!is_string($plain) || $plain === '') {
            return;
        }

        if (!$user instanceof Model) {
            return;
        }

        if (!$force && !$this->hasher->needsRehash($user->getAuthPassword())) {
            return;
        }

        $this->persistRehashedPassword($user, $plain);
    }

    /**
     * Instantiate a fresh copy of the configured Eloquent model.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model
     */
    protected function createModel(): Authenticatable&Model
    {
        $class = $this->model;

        $instance = new $class;

        assert($instance instanceof Authenticatable && $instance instanceof Model);

        return $instance;
    }

    /**
     * Build a fresh Eloquent query rooted at the supplied model.
     * Single localised site for the dynamic-class `newQuery()` call
     * so any phpstan suppressions live in one place.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model  $model
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>
     */
    private function freshQuery(Authenticatable&Model $model): Builder
    {
        // See `persistRehashedPassword()` for the suppression
        // rationale (larastan static-aliases the instance method).
        // @phpstan-ignore staticMethod.dynamicCall
        return $model->newQuery();
    }

    /**
     * Drop non-string keys, empty keys, and any key containing
     * "password" so the remainder can safely compose `where()` calls.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return array<string, mixed>
     */
    private function filterCredentialKeys(#[\SensitiveParameter] array $credentials): array
    {
        $filtered = [];

        foreach ($credentials as $key => $value) {

            if (!is_string($key) || $key === '' || str_contains($key, 'password')) {
                continue;
            }

            $filtered[$key] = $value;
        }

        return $filtered;
    }

    /**
     * Apply each credential to the query as a `where`/`whereIn`/
     * closure clause. Returns `false` if any value is unsupported;
     * the caller should treat `false` as "refuse to authenticate".
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
     * @param  array<string, mixed>  $credentials
     * @return bool
     */
    private function applyCredentialClauses(
        Builder $query,
        #[\SensitiveParameter] array $credentials,
    ): bool {

        foreach ($credentials as $key => $value) {
            if (!$this->applyCredentialClause($query, $key, $value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Apply a single credential clause to the query. Returns `false`
     * if the value is not a supported type.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
     * @param  string  $key
     * @param  mixed  $value
     * @return bool
     */
    private function applyCredentialClause(
        Builder $query,
        string $key,
        mixed $value,
    ): bool {

        return match (true) {
            is_array($value)           => $this->applyArrayClause($query, $key, $value),
            $value instanceof \Closure => $this->applyClosureClause($query, $value),
            is_string($value),
            is_int($value),
            is_bool($value),
            $value instanceof \Stringable => $this->applyScalarClause($query, $key, $value),
            default                       => false,
        };
    }

    /**
     * Apply an `IN` clause built from an array of credential values.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
     * @param  string  $key
     * @param  array<array-key, mixed>  $values
     * @return bool
     */
    private function applyArrayClause(
        Builder $query,
        string $key,
        array $values,
    ): bool {
        // @phpstan-ignore staticMethod.dynamicCall
        $query->whereIn($key, $values);

        return true;
    }

    /**
     * Hand the supplied query to a credential closure for additional
     * `where` composition.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
     * @param  \Closure(\Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>): mixed  $callback
     * @return bool
     */
    private function applyClosureClause(Builder $query, \Closure $callback): bool
    {
        $callback($query);

        return true;
    }

    /**
     * Apply a scalar `=` clause for a string/int/bool/Stringable
     * credential value.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
     * @param  string  $key
     * @param  bool|int|string|\Stringable  $value
     * @return bool
     */
    private function applyScalarClause(
        Builder $query,
        string $key,
        bool|int|string|\Stringable $value,
    ): bool {
        $query->where($key, $value);

        return true;
    }

    /**
     * Persist a freshly hashed password onto an Eloquent user model.
     * Localised so the dynamic-class phpstan suppression lives here.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model  $user
     * @param  string  $plain
     * @return void
     */
    private function persistRehashedPassword(
        Authenticatable&Model $user,
        #[\SensitiveParameter] string $plain,
    ): void {
        // larastan static-aliases forceFill/save via @method static
        // annotations even though they are instance methods; the
        // suppression is unavoidable while the model class is
        // resolved at runtime via config.
        // @phpstan-ignore staticMethod.dynamicCall, staticMethod.dynamicCall
        $user->forceFill([
            $user->getAuthPasswordName() => $this->hasher->make($plain),
        ])->save();
    }
}
