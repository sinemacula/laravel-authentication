<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;

/**
 * Provides a default `HasVerifiableIdentifiers` and `HasChangeableIdentifiers`
 * implementation on an Eloquent identity: the identifier of a type is the
 * attribute named after the type (`email`), and its verification time is
 * `<type>_verified_at` (`email_verified_at`, the column Laravel's own email
 * verification uses). Override `getVerifiedAtName()` to use other columns.
 * Declare `HasChangeableIdentifiers` on the model to change its identifiers
 * through `Auth::identifierChanges()`.
 *
 * Both attributes must be loaded: a model selected without one throws rather
 * than being read as unverified or as having no identifier, so a partial select
 * surfaces as a misconfiguration.
 *
 * When an identifier changes, its verification no longer applies: set its
 * `<type>_verified_at` to `null` with it, unless the change replaces it with
 * one already proven (`replaceIdentifier()` records that one as verified).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers
 */
trait ProvidesIdentifierVerification
{
    /**
     * The identity's current identifier of the type, or `null` when it has
     * none.
     *
     * @param  string  $type
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function getIdentifierForVerification(string $type): ?string
    {
        $identifier = $this->loadedVerificationAttribute(IdentifierType::assertValid($type));

        return is_string($identifier) && $identifier !== '' ? $identifier : null;
    }

    /**
     * Whether the identifier of the type has a verification time.
     *
     * @param  string  $type
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function hasVerifiedIdentifier(string $type): bool
    {
        return $this->loadedVerificationAttribute($this->getVerifiedAtName(IdentifierType::assertValid($type))) !== null;
    }

    /**
     * Record the identifier as verified now, in one transaction on the
     * identity's connection: the row is read again under a lock (`FOR UPDATE`
     * where the database has one), and `<type>_verified_at` is set only when
     * the row's identifier is the one given, byte for byte (not merely equal
     * under the column's collation), and its verification time is still `null`.
     * The model is updated to match only when the row changed. The write fires
     * no model events and leaves `updated_at` alone.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     *
     * @imperative
     */
    public function markIdentifierAsVerified(string $type, string $identifier): bool
    {
        $column = $this->getVerifiedAtName(IdentifierType::assertValid($type));

        $verifiedAt = $this->getConnection()->transaction(function () use ($type, $identifier, $column): mixed {

            $stored = (array) $this->identityRow()->lockForUpdate()->first([$type, $column]);

            if ($stored === [] || $stored[$type] !== $identifier || $stored[$column] !== null) {
                return null;
            }

            $verifiedAt = $this->fromDateTime(Carbon::now());

            return $this->identityRow()->update([$column => $verifiedAt]) === 1 ? $verifiedAt : null;
        });

        if ($verifiedAt === null) {
            return false;
        }

        $this->forceFill([$column => $verifiedAt])->syncOriginalAttribute($column);

        return true;
    }

    /**
     * Replace the identifier with one already proven and record it as verified
     * now, in one transaction on the identity's connection: the row is read
     * again under a lock (`FOR UPDATE` where the database has one), and written
     * only when its identifier is `$current` byte for byte (not merely equal
     * under the column's collation; `null` stands for none, a `null` or empty
     * column). `updated_at` is set too when the model keeps timestamps. The
     * model is updated to match only when the row changed. The write fires no
     * model events, and a violation of a unique index on the column propagates.
     *
     * @param  string  $type
     * @param  ?string  $current
     * @param  string  $replacement
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     *
     * @imperative
     */
    public function replaceIdentifier(string $type, ?string $current, string $replacement): bool
    {
        $column = $this->getVerifiedAtName(IdentifierType::assertValid($type));

        $values = $this->getConnection()->transaction(function () use ($type, $current, $replacement, $column): ?array {

            $stored = (array) $this->identityRow()->lockForUpdate()->first([$type]);

            if ($stored === [] || !self::isIdentifier($stored[$type], $current)) {
                return null;
            }

            $values = [$type => $replacement, $column => $this->fromDateTime(Carbon::now())];
            $stamp  = $this->usesTimestamps() ? $this->getUpdatedAtColumn() : null;

            if ($stamp !== null) {
                $values[$stamp] = $values[$column];
            }

            return $this->identityRow()->update($values) === 1 ? $values : null;
        });

        if ($values === null) {
            return false;
        }

        $this->forceFill($values)->syncOriginalAttributes(array_keys($values));

        return true;
    }

    /**
     * The column holding when the identifier of the type was verified.
     *
     * @param  string  $type
     * @return string
     */
    protected function getVerifiedAtName(string $type): string
    {
        return "{$type}_verified_at";
    }

    /**
     * A query for the identity's own row, without its scopes.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function identityRow(): Builder
    {
        return $this->newQueryWithoutScopes()->whereKey($this->getKey())->toBase();
    }

    /**
     * Whether the stored value of an identifier column is the identifier given,
     * byte for byte; `null` stands for none, which a `null` or empty column
     * holds.
     *
     * @param  mixed  $stored
     * @param  ?string  $identifier
     * @return bool
     */
    private static function isIdentifier(mixed $stored, ?string $identifier): bool
    {
        return $identifier === null ? $stored === null || $stored === '' : $stored === $identifier;
    }

    /**
     * Read a verification attribute, throwing when the model was loaded without
     * it.
     *
     * @param  string  $name
     * @return mixed
     *
     * @throws \LogicException
     */
    private function loadedVerificationAttribute(string $name): mixed
    {
        if (!array_key_exists($name, $this->getAttributes())) {

            $message = sprintf(
                'Cannot read the verification of %s: its `%s` attribute is not loaded. Select the column or override getVerifiedAtName().',
                static::class,
                $name,
            );

            throw new \LogicException($message);
        }

        return WriteConnection::during($this, fn (): mixed => $this->getAttribute($name));
    }
}
