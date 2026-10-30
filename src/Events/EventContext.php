<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Audience\PrincipalType;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Concerns\SerializesLiveModels;
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
 * Everything but the four models is the snapshot, fixed when the context is
 * built: when (`occurredAt`), the guard, the client, the method, the
 * credential's id and scopes, the morph class (an Eloquent model's morph class,
 * else the class name) and identifier of the identity, the principal and the
 * tenant, the principal's categorical type (`principalCategory`, as
 * `Auth::type()` reports it), and the device's identifier. It is the record an
 * audit sink keeps, and `toArray()` gives it as scalars. The models are a
 * convenience: a synchronous listener gets the instances the package holds, and
 * after a queue each Eloquent model is fetched again in its state then (with
 * the relations it had loaded), or is `null` once its row is gone; a part that
 * is not an Eloquent model does not cross a queue and is `null` after one. A
 * queued model is current state, not evidence of what was authorised. `scopes`
 * is `null` for a human identity's session, which no credential limits, and the
 * list the credential grants otherwise (`[]` grants none). Never carries a
 * token, a key, a digest, a password or any other secret.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, mixed>
 */
final readonly class EventContext implements Arrayable
{
    use SerializesLiveModels;

    /** @var \Carbon\CarbonImmutable When the event was built. */
    public CarbonImmutable $occurredAt;

    /** @var ?string The identity's morph class (an Eloquent model's morph class, or its class name) when the event was built. */
    public ?string $identityMorphClass;

    /** @var ?string The identity's auth identifier when the event was built. */
    public ?string $identityId;

    /** @var ?string The principal's morph class (an Eloquent model's morph class, or its class name), as a device records it, when the event was built. */
    public ?string $principalMorphClass;

    /** @var ?string The principal's identifier when the event was built. */
    public ?string $principalId;

    /** @var ?string The principal's categorical type (its own, else its tenant's), as `Auth::type()` reports it, when the event was built. */
    public ?string $principalCategory;

    /** @var ?string The tenant's morph class (an Eloquent model's morph class, or its class name) when the event was built. */
    public ?string $tenantMorphClass;

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

        $this->occurredAt          = CarbonImmutable::now();
        $this->identityMorphClass  = $identity  === null ? self::recordedOn($recorded, 'ownerType') : self::morphClassOf($identity);
        $this->identityId          = $identity  === null ? self::recordedOn($recorded, 'owner') : IdentifierCoercion::stringify($identity->getAuthIdentifier());
        $this->principalMorphClass = $principal === null ? self::recordedOn($recorded, 'type') : PrincipalReference::type($principal);
        $this->principalId         = $principal === null ? self::recordedOn($recorded, 'id') : PrincipalReference::id($principal);
        $this->principalCategory   = self::categoryOf($principal, $tenant);
        $this->tenantMorphClass    = $tenant === null ? null : self::morphClassOf($tenant);
        $this->tenantId            = IdentifierCoercion::stringify($tenant?->getTenantIdentifier());
        $this->deviceId            = $device === null ? $deviceId : IdentifierCoercion::stringify($device->getDeviceIdentifier());
    }

    /**
     * Return the snapshot as scalars, the record an audit sink keeps: the time
     * as an ISO 8601 UTC string to the microsecond, and the client as its IP
     * address and user agent. The models are left out.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'occurred_at'           => $this->occurredAt->utc()->format('Y-m-d\TH:i:s.u\Z'),
            'guard'                 => $this->guard,
            'method'                => $this->method,
            'ip'                    => $this->client->ip,
            'user_agent'            => $this->client->userAgent,
            'identity_morph_class'  => $this->identityMorphClass,
            'identity_id'           => $this->identityId,
            'principal_morph_class' => $this->principalMorphClass,
            'principal_id'          => $this->principalId,
            'principal_category'    => $this->principalCategory,
            'tenant_morph_class'    => $this->tenantMorphClass,
            'tenant_id'             => $this->tenantId,
            'device_id'             => $this->deviceId,
            'credential_id'         => $this->credentialId,
            'scopes'                => $this->scopes,
        ];
    }

    /**
     * The principal's categorical type from what is loaded: its own, else the
     * tenant's; `null` without a principal, and when the principal or tenant
     * was loaded without its type, which is unknown here rather than a reason
     * to fail the flow the event reports.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return ?string
     */
    private static function categoryOf(?Principal $principal, ?Tenant $tenant): ?string
    {
        try {
            return $principal === null ? null : PrincipalType::loaded($principal, $tenant);
        } catch (\LogicException) {
            return null;
        }
    }

    /**
     * The morph class an identity or tenant is recorded by: an Eloquent model's
     * morph class, any other object's class name.
     *
     * @param  object  $subject
     * @return string
     */
    private static function morphClassOf(object $subject): string
    {
        return $subject instanceof Model ? $subject->getMorphClass() : $subject::class;
    }

    /**
     * What an Eloquent device row records, read from its attributes without a
     * query: its owner's morph class (`ownerType`) or identifier (`owner`), or
     * its principal's morph class (`type`) or identifier (`id`); `null` when
     * the row records none or there is no such row.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  'id'|'owner'|'ownerType'|'type'  $part
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
        $owner   = $blank->authenticatable();
        $columns = ['ownerType' => $owner->getMorphType(), 'owner' => $owner->getForeignKeyName(), 'type' => $type, 'id' => $id];

        return IdentifierCoercion::stringify($device->getAttributes()[$columns[$part]] ?? null);
    }
}
