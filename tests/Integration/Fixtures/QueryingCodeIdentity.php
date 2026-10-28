<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Identity fixture over `code_identities` that reads its identifier of a type,
 * and whether it is verified, with queries of its own instead of the attributes
 * it was loaded with, as an identity keeping them in other tables would; so a
 * test can tell which connection those reads use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 *
 * @internal
 */
final class QueryingCodeIdentity extends Model implements HasDevices, HasVerifiableIdentifiers, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesIdentifierVerification;

    /** @var string|null The table associated with the model. */
    protected $table = 'code_identities';

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

    /**
     * Eloquent relation builder for the identity's devices.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): Builder
    {
        return Device::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->getKey()); // @phpstan-ignore cast.string
    }
}
