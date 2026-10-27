<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * Identity fixture over the `verifiable_identities` table that reads its
 * identifier of a type, and whether it is verified, with queries of its own
 * instead of the attributes it was loaded with, as an identity keeping them in
 * other tables would.
 *
 * @property int $id
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class QueryingVerifiableIdentity extends Model implements HasVerifiableIdentifiers, Identity
{
    use Authenticatable, ProvidesIdentifierVerification;

    /** @var string|null The table associated with the model. */
    protected $table = 'verifiable_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identifier of the type, read with a query.
     *
     * @param  string  $type
     * @return ?string
     */
    #[\Override]
    public function getIdentifierForVerification(string $type): ?string
    {
        $identifier = self::query()->whereKey($this->getKey())->value($type);

        return is_string($identifier) && $identifier !== '' ? $identifier : null;
    }

    /**
     * Whether the identifier of the type is verified, read with a query.
     *
     * @param  string  $type
     * @return bool
     */
    #[\Override]
    public function hasVerifiedIdentifier(string $type): bool
    {
        return self::query()->whereKey($this->getKey())->whereNotNull("{$type}_verified_at")->exists();
    }
}
