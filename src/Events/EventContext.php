<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Sessions\PrincipalReference;

/**
 * Who and what a package event is about: the guard, the client the request came
 * from, the identity, principal, tenant and device, and the sign-in method.
 * Every package event carries one, so a single listener on
 * `AuthenticationEvent` can attribute them all the same way.
 *
 * A part the event's flow did not establish is `null`: a failure carries only
 * as much as it got to before it failed, and a device id a token named is kept
 * even when no device row was loaded.
 *
 * The identifiers are snapshots taken when the event is built, as strings: the
 * identity's auth identifier, the principal's recorded type and identifier, the
 * tenant's and the device's identifiers. They survive queueing unchanged, so
 * audit sinks should record them. The models are live references: a synchronous
 * listener gets the instances the package holds, and a queued listener gets
 * them re-fetched in their state when it runs (or a `ModelNotFoundException`
 * when one was deleted in between), as Laravel's `SerializesModels` does. A
 * principal, tenant or device that is not an Eloquent model is serialised as
 * the object itself. Never carries a token, a digest, a password or any other
 * secret.
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
    ) {
        $this->identityId    = IdentifierCoercion::stringify($identity?->getAuthIdentifier());
        $this->principalType = $principal === null ? null : PrincipalReference::type($principal);
        $this->principalId   = $principal === null ? null : PrincipalReference::id($principal);
        $this->tenantId      = IdentifierCoercion::stringify($tenant?->getTenantIdentifier());
        $this->deviceId      = $device === null ? $deviceId : IdentifierCoercion::stringify($device->getDeviceIdentifier());
    }
}
