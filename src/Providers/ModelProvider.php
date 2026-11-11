<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Providers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Casts\NormalizedIdentifier;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Database\WriteConnection;

/**
 * Eloquent-backed identity provider that reads identities on the write
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @inheritable
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

        /** Fully-qualified Eloquent model class name to authenticate against. */
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
     * Eager loads run as separate queries the write-PDO flag does not reach,
     * hence `WriteConnection::during()`.
     *
     * @param  mixed  $identifier
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function retrieveById(mixed $identifier): ?Authenticatable
    {
        $model = $this->createModel();
        $query = $this->freshQuery($model)->where($model->getAuthIdentifierName(), $identifier);

        /** @var (\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model)|null */
        return WriteConnection::during($model, static fn (): mixed => $query->first());
    }

    /**
     * Inert in this stateless package.
     *
     * @param  mixed  $identifier
     * @param  mixed  $token
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function retrieveByToken(mixed $identifier, #[\SensitiveParameter] mixed $token): ?Authenticatable
    {
        return null;
    }

    /**
     * Inert in this stateless package.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $token
     * @return void
     */
    #[\Override]
    public function updateRememberToken(Authenticatable $user, #[\SensitiveParameter] mixed $token): void {}

    /**
     * Retrieve a user by the given credentials, ignoring password keys and
     * normalising identifier attributes first.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function retrieveByCredentials(#[\SensitiveParameter] array $credentials): ?Authenticatable
    {
        $filtered = $this->filterCredentialKeys($credentials);

        if ($filtered === []) {
            return null;
        }

        $model      = $this->createModel();
        $normalized = $this->normalizeIdentifiers($model, $filtered);

        if ($normalized === null) {
            return null;
        }

        $query = $this->freshQuery($model);

        /** @var (\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model)|null */
        return WriteConnection::during($model, fn (): mixed => $this->applyCredentialClauses($query, $normalized) ? $query->first() : null);
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

        $hash = WriteConnection::during($user, static fn (): mixed => $user->getAuthPassword());

        // Eloquent returns the raw attribute, null for an account without one
        // @phpstan-ignore function.alreadyNarrowedType
        return is_string($hash) && $this->hasher->check($plain, $hash);
    }

    /**
     * Rehash the user's password when its hash is outdated, or always when
     * forced.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<array-key, mixed>  $credentials
     * @param  bool  $force
     * @return void
     */
    #[\Override]
    public function rehashPasswordIfRequired(Authenticatable $user, #[\SensitiveParameter] array $credentials, bool $force = false): void
    {
        $plain = $credentials['password'] ?? null;

        if (!is_string($plain) || $plain === '' || !$user instanceof Model) {
            return;
        }

        $hash = WriteConnection::during($user, static fn (): mixed => $user->getAuthPassword());

        // Eloquent returns the raw attribute, null for an account without one
        // @phpstan-ignore function.alreadyNarrowedType, staticMethod.dynamicCall
        if (!is_string($hash) || ($user->getAttributes()[$user->getAuthPasswordName()] ?? null) !== $hash) {
            return;
        }

        if (!$force && !$this->hasher->needsRehash($hash)) {
            return;
        }

        $this->persistRehashedPassword($user, $hash, $this->hasher->make($plain));
    }

    /**
     * Instantiate a fresh copy of the configured Eloquent model.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model
     */
    protected function createModel(): Authenticatable&Model
    {
        $class = $this->model;

        /** @var \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model */
        return new $class;
    }

    /**
     * Build a fresh query for the model, pinned to the write connection.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model  $model
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model>
     */
    private function freshQuery(Authenticatable&Model $model): Builder
    {
        // @phpstan-ignore staticMethod.dynamicCall
        return WriteConnection::query($model->newQuery());
    }

    /**
     * Drop the keys that are empty, not strings, name a password or are not
     * valid column identifiers.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return array<string, mixed>
     */
    private function filterCredentialKeys(#[\SensitiveParameter] array $credentials): array
    {
        $filtered = [];

        foreach ($credentials as $key => $value) {

            if (!is_string($key) || $key === '' || str_contains(strtolower($key), 'password')) {
                continue;
            }

            // The key becomes a column name, so it must be a plain identifier
            if (preg_match('/^[a-zA-Z_]\w*(\.[a-zA-Z_]\w*)*$/', $key) !== 1) {
                continue;
            }

            $filtered[$key] = $value;
        }

        return $filtered;
    }

    /**
     * Apply each credential to the query, or return `false` when any value is
     * unsupported.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model>  $query
     * @param  array<string, mixed>  $credentials
     * @return bool
     */
    private function applyCredentialClauses(Builder $query, #[\SensitiveParameter] array $credentials): bool
    {
        foreach ($credentials as $key => $value) {
            if (!$this->applyCredentialClause($query, $key, $value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Apply a single credential clause to the query, or return `false` when the
     * value is unsupported.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model>  $query
     * @param  string  $key
     * @param  mixed  $value
     * @return bool
     */
    private function applyCredentialClause(Builder $query, string $key, #[\SensitiveParameter] mixed $value): bool
    {
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
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model>  $query
     * @param  string  $key
     * @param  array<array-key, mixed>  $values
     * @return bool
     */
    private function applyArrayClause(Builder $query, string $key, #[\SensitiveParameter] array $values): bool
    {
        // @phpstan-ignore staticMethod.dynamicCall
        $query->whereIn($key, $values);

        return true;
    }

    /**
     * Hand the supplied query to a credential closure for additional `where`
     * composition.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model>  $query
     * @param  \Closure(\Illuminate\Database\Eloquent\Builder<\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model>): mixed  $callback
     * @return bool
     */
    private function applyClosureClause(Builder $query, \Closure $callback): bool
    {
        $callback($query);

        return true;
    }

    /**
     * Apply a scalar `=` clause for a string/int/bool/Stringable credential
     * value.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model>  $query
     * @param  string  $key
     * @param  bool|int|string|\Stringable  $value
     * @return bool
     */
    private function applyScalarClause(Builder $query, string $key, #[\SensitiveParameter] bool|int|string|\Stringable $value): bool
    {
        $query->where($key, $value);

        return true;
    }

    /**
     * Normalise the credentials for attributes the model designates as
     * identifiers, or return `null` when one of them cannot be an identifier.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model  $model
     * @param  array<string, mixed>  $credentials
     * @return ?array<string, mixed>
     */
    private function normalizeIdentifiers(Authenticatable&Model $model, #[\SensitiveParameter] array $credentials): ?array
    {
        // @phpstan-ignore staticMethod.dynamicCall
        $casts = $model->getCasts();
        // @phpstan-ignore staticMethod.dynamicCall
        $table = $model->getTable() . '.';

        foreach ($credentials as $key => $value) {

            $attribute = str_starts_with($key, $table) ? substr($key, strlen($table)) : $key;
            $cast      = NormalizedIdentifier::fromDeclaration($casts[$attribute] ?? null);

            if ($cast === null) {
                continue;
            }

            $normalized = is_array($value) ? $this->normalizeEach($cast, $value) : $this->normalizeOne($cast, $value);

            if ($normalized === null) {
                return null;
            }

            $credentials[$key] = $normalized;
        }

        return $credentials;
    }

    /**
     * Normalise each string element of an identifier credential, or return
     * `null` when one of them cannot be an identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Casts\NormalizedIdentifier  $cast
     * @param  array<array-key, mixed>  $values
     * @return ?array<array-key, mixed>
     */
    private function normalizeEach(NormalizedIdentifier $cast, #[\SensitiveParameter] array $values): ?array
    {
        foreach ($values as $index => $value) {

            $normalized = $this->normalizeOne($cast, $value);

            if ($normalized === null) {
                return null;
            }

            $values[$index] = $normalized;
        }

        return $values;
    }

    /**
     * Normalise a string identifier credential (`null` when it cannot be an
     * identifier), leaving any other value as given.
     *
     * @param  \SineMacula\Laravel\Authentication\Casts\NormalizedIdentifier  $cast
     * @param  mixed  $value
     * @return mixed
     */
    private function normalizeOne(NormalizedIdentifier $cast, #[\SensitiveParameter] mixed $value): mixed
    {
        return is_string($value) || $value instanceof \Stringable ? $cast->normalize((string) $value) : $value;
    }

    /**
     * Write a new password hash for the user, provided the stored hash is still
     * the one it authenticated with.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model  $user
     * @param  string  $authenticated
     * @param  string  $rehashed
     * @return void
     */
    private function persistRehashedPassword(Authenticatable&Model $user, string $authenticated, string $rehashed): void
    {
        $column = $user->getAuthPasswordName();

        // @phpstan-ignore staticMethod.dynamicCall, staticMethod.dynamicCall
        $query = $user->newQueryWithoutScopes()->whereKey($user->getKey())->where($column, $authenticated);

        if ($query->toBase()->update([$column => $rehashed]) !== 1) {
            return;
        }

        // @phpstan-ignore staticMethod.dynamicCall, staticMethod.dynamicCall
        $user->forceFill([$column => $rehashed])->syncOriginalAttribute($column);
    }
}
