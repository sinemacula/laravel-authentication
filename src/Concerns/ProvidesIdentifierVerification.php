<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;

/**
 * Provides a default `HasVerifiableIdentifiers` implementation on an Eloquent
 * identity: the identifier of a type is the attribute named after the type
 * (`email`), and its verification time is `<type>_verified_at`
 * (`email_verified_at`, the column Laravel's own email verification uses).
 * Override `getVerifiedAtName()` to use other columns.
 *
 * Both attributes must be loaded: a model selected without one throws rather
 * than being read as unverified or as having no identifier, so a partial select
 * surfaces as a misconfiguration.
 *
 * When an identifier changes, its verification no longer applies: set its
 * `<type>_verified_at` to `null` with it.
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
     * Record the identifier as verified now, with one conditional update on
     * the identity's row: `WHERE <key> = :id AND <type> = :identifier AND
     * <type>_verified_at IS NULL`. The model is updated to match only when
     * that row changed. The write fires no model events and leaves
     * `updated_at` alone.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function markIdentifierAsVerified(string $type, string $identifier): bool
    {
        $column     = $this->getVerifiedAtName(IdentifierType::assertValid($type));
        $verifiedAt = $this->fromDateTime(Carbon::now());

        $query = WriteConnection::query($this->newQueryWithoutScopes()->whereKey($this->getKey())->where($type, $identifier)->whereNull($column));

        if ($query->toBase()->update([$column => $verifiedAt]) !== 1) {
            return false;
        }

        $this->forceFill([$column => $verifiedAt])->syncOriginalAttribute($column);

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
