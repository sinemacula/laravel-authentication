<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * Provides a default `HasVerifiableIdentifiers` implementation on an Eloquent
 * identity, verified at `<type>_verified_at`.
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
     * Record the identifier as verified now, when the locked row still holds it
     * byte for byte and is unverified.
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
     * The identities whose identifier of the type is the given one in its
     * normal form, byte for byte, and verified, read on the write connection
     * with the model's global scopes.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return \Illuminate\Database\Eloquent\Collection<int, static>
     *
     * @throws \InvalidArgumentException
     */
    public static function holdingVerifiedIdentifier(string $type, #[\SensitiveParameter] string $identifier): Collection
    {
        $model      = new static;
        $normalized = Container::getInstance()->make(IdentifierVerifier::class)->canonical(IdentifierType::assertValid($type), $identifier);

        if ($normalized === null) {
            return $model->newCollection();
        }

        $query = WriteConnection::query($model->newQuery())->where($type, $normalized)->whereNotNull($model->getVerifiedAtName($type));

        // A collation can match another spelling of the identifier
        return WriteConnection::during($model, static fn (): Collection => $query->get())
            ->filter(static fn (self $identity): bool => $identity->getRawOriginal($type) === $normalized)
            ->values();
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
