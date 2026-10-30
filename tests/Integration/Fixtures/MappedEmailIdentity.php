<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * 2D identity fixture, stored in `mapped_email_identities`, whose email address
 * lives in an `email_address` column: it reports the identifier of the `email`
 * type through `HasVerifiableIdentifiers`, as the contract allows, and has no
 * attribute named after the type. It has no identifier of any other type, and
 * says so with a `LogicException`, as `ProvidesIdentifierVerification` does for
 * a column a model does not load.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property ?string $email_address
 * @property ?string $password
 *
 * @internal
 */
final class MappedEmailIdentity extends Model implements HasDevices, HasVerifiableIdentifiers, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'mapped_email_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identity's devices of the shipped model.
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

    /**
     * The email address from its own column; no identifier of another type.
     *
     * @param  string  $type
     * @return ?string
     *
     * @throws \LogicException
     */
    #[\Override]
    public function getIdentifierForVerification(string $type): ?string
    {
        if ($type !== 'email') {
            throw new \LogicException(sprintf('%s has no [%s] identifier.', self::class, $type));
        }

        $address = $this->getAttribute('email_address');

        return is_string($address) ? $address : null;
    }

    /**
     * Every email address it holds is verified.
     *
     * @param  string  $type
     * @return bool
     */
    #[\Override]
    public function hasVerifiedIdentifier(string $type): bool
    {
        return $type === 'email';
    }

    /**
     * Nothing is recorded: the fixture's address is verified already.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function markIdentifierAsVerified(string $type, string $identifier): bool
    {
        return false;
    }
}
