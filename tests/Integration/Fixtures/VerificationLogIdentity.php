<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * Identity fixture over the `verifiable_identities` table whose email address
 * also counts as verified while a row in `identifier_verifications` names the
 * identity, as an application might record verifications outside the identity
 * row: its `email_verified_at` accessor falls back to that table.
 *
 * @property int $id
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VerificationLogIdentity extends Model implements HasVerifiableIdentifiers, Identity
{
    use Authenticatable, ProvidesIdentifierVerification;

    /** @var string|null The table associated with the model. */
    protected $table = 'verifiable_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * When the email address was verified: the identity's own column, or the
     * time an `identifier_verifications` row records.
     *
     * @return \Illuminate\Database\Eloquent\Casts\Attribute<mixed, never>
     */
    protected function emailVerifiedAt(): Attribute
    {
        return Attribute::get(fn (mixed $value): mixed => $value ?? $this->getConnection()
            ->table('identifier_verifications')
            ->where('identity_id', $this->getKey())
            ->value('verified_at'));
    }
}
