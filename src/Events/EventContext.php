<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Sessions\PrincipalReference;

/**
 * Who and what a package event is about: the guard, the client the request came
 * from, the identity, principal, tenant and device, the sign-in method, and the
 * credential (an API key or a passkey) with the scopes it grants. Every package
 * event carries one, so a single listener on `AuthenticationEvent` can
 * attribute them all the same way.
 *
 * A part the event's flow did not establish is `null`: a failure carries only
 * as much as it got to before it failed, and a device id a token named is kept
 * even when no device row was loaded. An event about the device row itself (a
 * revocation, or a refresh or switch refused on the row's own state before its
 * owner was read) is built with `fromDevice`: an identity or principal it does
 * not hold then takes the snapshot of the owner and the principal the row
 * records; devices record no tenant. Every other event keeps the snapshots of
 * what it holds, so an identity's sign-out everywhere, a pending choice of
 * principal or a refused switch to another principal names no principal, even
 * when it carries a device.
 *
 * The identifiers are snapshots taken when the event is built, as strings: the
 * identity's auth identifier, the principal's recorded type and identifier, the
 * tenant's and the device's identifiers. They survive queueing unchanged, so
 * audit sinks should record them. The models are live references: a synchronous
 * listener gets the instances the package holds, and a queued listener gets
 * them re-fetched in their state when it runs (or a `ModelNotFoundException`
 * when one was deleted in between), as Laravel's `SerializesModels` does. A
 * principal, tenant or device that is not an Eloquent model is serialised as
 * the object itself. The credential's id and scopes are plain strings, so they
 * survive queueing unchanged too: `scopes` is `null` for a human identity's
 * session, which no credential limits, and the list the credential grants
 * otherwise (`[]` grants none). Never carries a token, a key, a digest, a
 * password or any other secret.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EventContext
{
    use SerializesModels;

    /** @var ?string The identity's auth identifier when the event was built. */
    public ?string $identityId;

    /** @var ?string The principal's recorded type (its morph class, or its class name) when the event was built. */
    public ?string $principalType;

    /** @var ?string The principal's identifier when the event was built. */
    public ?string $principalId;

    /** @var ?string The tenant's identifier when the event was built. */
    public ?string $tenantId;

    /** @var ?string The device's identifier, or the one a token or pin named when no device was loaded. */
    public ?string $deviceId;

    /**
     * Constructor.
     *
     * @param  ?string  $guard
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  ?string  $method
     * @param  ?string  $deviceId
     * @param  bool  $fromDevice
     * @param  ?string  $credentialId
     * @param  ?list<string>  $scopes
     */
    public function __construct(

        /** Name of the guard the event is about; `null` only for a device that records none. */
        public ?string $guard,

        /** Client of the request being served (in a queue job or a console command, that process's request). */
        public ClientContext $client,

        /** Identity the event is about, if known. */
        public ?Identity $identity = null,

        /** Principal the identity acts as, if known. */
        public ?Principal $principal = null,

        /** Tenant the principal acts within, if known and there is one. */
        public ?Tenant $tenant = null,

        /** Device holding the session, if one was loaded. */
        public ?Device $device = null,

        /** Name of the sign-in method; for a device's events, the method its session records. */
        public ?string $method = null,

        // A device id a token or pin named, kept when no device row was loaded.
        ?string $deviceId = null,

        // Whether the event is about the device row itself, so the owner and
        // principal the row records stand in for those not given.
        bool $fromDevice = false,

        /** Identifier of the API key or passkey the event concerns, if any. */
        #[\SensitiveParameter]
        public ?string $credentialId = null,

        /** Scopes the credential grants; `null` for a human identity's session, which no credential limits. */
        public ?array $scopes = null,
    ) {
        $recorded = $fromDevice ? $device : null;

        $this->identityId    = $identity  === null ? self::recordedOn($recorded, 'owner') : IdentifierCoercion::stringify($identity->getAuthIdentifier());
        $this->principalType = $principal === null ? self::recordedOn($recorded, 'type') : PrincipalReference::type($principal);
        $this->principalId   = $principal === null ? self::recordedOn($recorded, 'id') : PrincipalReference::id($principal);
        $this->tenantId      = IdentifierCoercion::stringify($tenant?->getTenantIdentifier());
        $this->deviceId      = $device === null ? $deviceId : IdentifierCoercion::stringify($device->getDeviceIdentifier());
    }

    /**
     * What an Eloquent device row records, read from its attributes without a
     * query: its owner's identifier (`owner`), or its principal's type (`type`)
     * or identifier (`id`); `null` when the row records none or there is no
     * such row.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  'id'|'owner'|'type'  $part
     * @return ?string
     */
    private static function recordedOn(?Device $device, string $part): ?string
    {
        if (!$device instanceof EloquentDevice || !$device instanceof Model) {
            return null;
        }

        [$type, $id] = PrincipalReference::columns($device);

        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice $blank */
        $blank   = $device->newInstance();
        $columns = ['owner' => $blank->authenticatable()->getForeignKeyName(), 'type' => $type, 'id' => $id];

        return IdentifierCoercion::stringify($device->getAttributes()[$columns[$part]] ?? null);
    }
}
