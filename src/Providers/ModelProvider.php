<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Providers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Database\WriteConnection;

/**
 * Eloquent-backed identity provider.
 *
 * Mirrors the surface of Laravel's `EloquentUserProvider` minus the remember-me
 * token methods, which are inert for this stateless package. Consumers may
 * subclass `createModel()` or `retrieveByCredentials()` for tenant scoping,
 * soft-delete exclusion, or other domain-specific lookups.
 *
 * Identity lookups decide authentication, so they read from the write
 * connection, together with any relations the identity model eager-loads; a
 * subclass that builds its own query must do the same (see `WriteConnection`).
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
     * The lookup runs inside `WriteConnection::during()` for the model, so
     * relations the identity eager-loads (`$with`) come from the writer as
     * well, on whichever connection they live: Eloquent runs each eager load as
     * a separate query that the root query's write-PDO flag does not reach.
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
     * Inert in this stateless package: returns `null`. Implemented only to
     * satisfy `UserProvider`.
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
     * Inert in this stateless package: empty no-op. Implemented only to satisfy
     * `UserProvider`.
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
     * Password keys are stripped before query composition so the hasher stays
     * the single source of password verification. An empty filtered set returns
     * `null` rather than running a where-less query.
     *
     * A credential for an attribute the model designates as an identifier
     * (`Casts\NormalisedIdentifier`) is normalised first, as the attribute is
     * when it is set, so the lookup matches the stored form whatever the
     * database's collation: a string through the type's normaliser, an array
     * element by element. A value the normaliser rejects cannot name an
     * account, so the lookup returns `null` without a query. Closures and other
     * values are applied as given.
     *
     * The clauses are applied inside the same `WriteConnection::during()`
     * window as the lookup, because a credential closure may run queries of its
     * own (a suspension lookup, say) that must not read a lagging replica.
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
        $normalised = $this->normaliseIdentifiers($model, $filtered);

        if ($normalised === null) {
            return null;
        }

        $query = $this->freshQuery($model);

        /** @var (\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model)|null */
        return WriteConnection::during($model, fn (): mixed => $this->applyCredentialClauses($query, $normalised) ? $query->first() : null);
    }

    /**
     * Validate the supplied credentials against the resolved user.
     *
     * The stored hash is read inside `WriteConnection::during()` for the user,
     * so a password getter that reads another table or lazily loads a
     * credential relation reads the writer: a hash a lagging replica still
     * holds cannot admit a password the primary has already replaced. An
     * account without a stored hash (a `null` password) is rejected.
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

        // The contract documents a string, but Eloquent returns the raw
        // attribute: null for an account stored without a password.
        // @phpstan-ignore function.alreadyNarrowedType
        return is_string($hash) && $this->hasher->check($plain, $hash);
    }

    /**
     * Rehash the user's password when the hash it authenticated with is
     * outdated (or always, when forced), for a caller that has just verified
     * the supplied password against it. No-ops when no password is supplied,
     * the user is not an Eloquent model, or its hash is not the model's own
     * password attribute (a `getAuthPassword()` that reads another table),
     * which this provider cannot write.
     *
     * The new hash is written with one conditional update on the model's
     * connection, `WHERE <key> = :id AND <password> = :authenticatedHash`, so a
     * password changed between the check and the rehash is never overwritten
     * with a hash of the old one; the model's attribute is updated only when
     * that row changed. The write fires no model events and leaves `updated_at`
     * alone: re-encoding the same password is not a change to the account.
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

        // The contract documents a string, but Eloquent returns the raw
        // attribute: null for an account stored without a password.
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
     * Build a fresh Eloquent query rooted at the supplied model and pinned to
     * the write connection, so a lagging read replica cannot resolve a
     * deactivated or deleted identity. Single localised site for the
     * dynamic-class `newQuery()` call so any phpstan suppressions live in one
     * place.
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
     * Drop non-string keys, empty keys, and any key containing "password" so
     * the remainder can safely compose `where()` calls.
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

            // Defense in depth: the key becomes an SQL column name downstream,
            // so reject anything that is not a valid identifier (optionally
            // dotted). Structurally prevents trailing dots, consecutive dots,
            // and any non-identifier byte from reaching `where()`/`whereIn()`.
            if (preg_match('/^[a-zA-Z_]\w*(\.[a-zA-Z_]\w*)*$/', $key) !== 1) {
                continue;
            }

            $filtered[$key] = $value;
        }

        return $filtered;
    }

    /**
     * Apply each credential to the query as a `where`/`whereIn`/ closure
     * clause. Returns `false` if any value is unsupported; the caller should
     * treat `false` as "refuse to authenticate".
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
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
     * Apply a single credential clause to the query. Returns `false` if the
     * value is not a supported type.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
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
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
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
     * Apply a scalar `=` clause for a string/int/bool/Stringable credential
     * value.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>  $query
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
     * identifiers, or return `null` when one of them cannot be an identifier. A
     * credential key qualified with the model's own table (`users.email`)
     * counts as its attribute.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model  $model
     * @param  array<string, mixed>  $credentials
     * @return ?array<string, mixed>
     */
    private function normaliseIdentifiers(Authenticatable&Model $model, #[\SensitiveParameter] array $credentials): ?array
    {
        // @phpstan-ignore staticMethod.dynamicCall
        $casts = $model->getCasts();
        // @phpstan-ignore staticMethod.dynamicCall
        $table = $model->getTable() . '.';

        foreach ($credentials as $key => $value) {

            $attribute = str_starts_with($key, $table) ? substr($key, strlen($table)) : $key;
            $cast      = NormalisedIdentifier::fromDeclaration($casts[$attribute] ?? null);

            if ($cast === null) {
                continue;
            }

            $normalised = is_array($value) ? $this->normaliseEach($cast, $value) : $this->normaliseOne($cast, $value);

            if ($normalised === null) {
                return null;
            }

            $credentials[$key] = $normalised;
        }

        return $credentials;
    }

    /**
     * Normalise each string element of an identifier credential, or return
     * `null` when one of them cannot be an identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier  $cast
     * @param  array<array-key, mixed>  $values
     * @return ?array<array-key, mixed>
     */
    private function normaliseEach(NormalisedIdentifier $cast, #[\SensitiveParameter] array $values): ?array
    {
        foreach ($values as $index => $value) {

            $normalised = $this->normaliseOne($cast, $value);

            if ($normalised === null) {
                return null;
            }

            $values[$index] = $normalised;
        }

        return $values;
    }

    /**
     * Normalise a string identifier credential (`null` when it cannot be an
     * identifier), leaving any other value as given.
     *
     * @param  \SineMacula\Laravel\Authentication\Casts\NormalisedIdentifier  $cast
     * @param  mixed  $value
     * @return mixed
     */
    private function normaliseOne(NormalisedIdentifier $cast, #[\SensitiveParameter] mixed $value): mixed
    {
        return is_string($value) || $value instanceof \Stringable ? $cast->normalise((string) $value) : $value;
    }

    /**
     * Write a new password hash for the user, provided the stored hash is still
     * the one it authenticated with, and mirror it on the model when it was
     * written.
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
