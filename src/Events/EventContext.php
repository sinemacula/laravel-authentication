<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\MorphClass;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Who and what a package event is about, as plain values: the guard, the client
 * the request came from, the identity, principal, tenant and session, each by
 * morph class and identifier, the sign-in method, the credential (an API key or
 * a passkey) with the scopes it grants, and, for what an external provider's
 * result was redeemed into, the connection and the authorisation request's
 * public reference. Every package event carries one, so a single listener on
 * `AuthenticationEvent` can attribute them all the same way.
 *
 * It is an allowlist of values fixed when the context is built, never a model:
 * the identity, principal, tenant and session it is built from are read once,
 * and none of them is kept, so the event crosses a queue as it is, its restore
 * runs no query and cannot fail on a row that is gone, and a listener that
 * needs a model loads it itself, on the write connection, from the type and
 * identifier. The morph class is an Eloquent model's morph class, else the
 * class name, which also stands for a model an enforced morph map leaves out.
 * `toArray()` gives the record an audit sink keeps.
 *
 * A part the event's flow did not establish is `null`: a failure carries only
 * as much as it got to before it failed, the session before one exists has no
 * identifier, and a session id a token named is kept even when no session row
 * was loaded. An event about the session row itself (a revocation, or a refresh
 * or switch refused on the row's own state before its owner was read) is built
 * with `fromSession`: an identity, principal or tenant it is not given then
 * takes the owner, the principal and the active tenant's identifier the row
 * records (a tenant has no morph class there: the row records only its opaque
 * identifier). Every other event names only what it is given, so an identity's
 * sign-out everywhere, a pending choice of principal or a refused switch to
 * another principal names no principal, even when it names a session. `scopes`
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
    /** @var \Carbon\CarbonImmutable When the event was built. */
    public CarbonImmutable $occurredAt;

    /** @var ?string The identity's morph class (an Eloquent model's morph class, or its class name) when the event was built. */
    public ?string $identityType;

    /** @var ?string The identity's auth identifier when the event was built. */
    public ?string $identityId;

    /** @var ?string The principal's morph class (an Eloquent model's morph class, or its class name), as a session records it, when the event was built. */
    public ?string $principalType;

    /** @var ?string The principal's identifier when the event was built. */
    public ?string $principalId;

    /** @var ?string The tenant's morph class (an Eloquent model's morph class, or its class name) when the event was built. */
    public ?string $tenantType;

    /** @var ?string The tenant's identifier when the event was built. */
    public ?string $tenantId;

    /** @var ?string The session's identifier, or the one a token or pin named when no session was loaded. */
    public ?string $sessionId;

    /**
     * Constructor.
     *
     * @param  ?string  $guard
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?string  $method
     * @param  ?string  $sessionId
     * @param  bool  $fromSession
     * @param  ?string  $credentialId
     * @param  ?list<string>  $scopes
     * @param  ?string  $connectionId
     * @param  ?string  $requestReference
     */
    public function __construct(

        /** Name of the guard the event is about; `null` only for a session that records none, or a verification link refused before its guard could be trusted. */
        public ?string $guard,

        /** Client the flow was given, or the guard's request's for a flow that takes none. */
        public ClientContext $client,

        // Identity the event is about, if known; only its type and identifier
        // are kept.
        ?Identity $identity = null,

        // Principal the identity acts as, if known; only its type and
        // identifier are kept.
        ?Principal $principal = null,

        // The active tenant, the one the principal acts in, if known and there
        // is one; only its type and identifier are kept.
        ?Tenant $tenant = null,

        // The session, if one was loaded; only its identifier is kept.
        ?Session $session = null,

        /** Name of the sign-in method; for a session's events, the method it records, or the one a step-up or reauthentication proved it with. */
        public ?string $method = null,

        // A session id a token or pin named, kept when no session row was
        // loaded.
        ?string $sessionId = null,

        // Whether the event is about the session row itself, so the owner and
        // principal the row records stand in for those not given.
        bool $fromSession = false,

        /** Identifier of the API key or passkey the event concerns, if any. */
        #[\SensitiveParameter]
        public ?string $credentialId = null,

        /** Scopes the credential grants; `null` for a human identity's session, which no credential limits. */
        public ?array $scopes = null,

        /** The connection (the configured external provider) a redeemed external result came through, for a redemption's own events. */
        public ?string $connectionId = null,

        /** The public reference of the authorisation request a redeemed external result answered, opaque, when the result had one. */
        public ?string $requestReference = null,
    ) {
        $recorded = $fromSession ? $session : null;

        $this->occurredAt    = CarbonImmutable::now();
        $this->identityType  = $identity  === null ? self::recordedOn($recorded, 'ownerType') : MorphClass::of($identity);
        $this->identityId    = $identity  === null ? self::recordedOn($recorded, 'owner') : IdentifierCoercion::stringify($identity->getAuthIdentifier());
        $this->principalType = $principal === null ? self::recordedOn($recorded, 'type') : MorphClass::of($principal);
        $this->principalId   = $principal === null ? self::recordedOn($recorded, 'id') : PrincipalReference::id($principal);
        $this->tenantType    = $tenant    === null ? null : MorphClass::of($tenant);
        $this->tenantId      = $tenant    === null ? self::recordedOn($recorded, 'tenant') : IdentifierCoercion::stringify($tenant->getTenantIdentifier());
        $this->sessionId     = $session   === null ? $sessionId : IdentifierCoercion::stringify($session->getSessionIdentifier());
    }

    /**
     * Return the context as scalars, the record an audit sink keeps: the time
     * as an ISO 8601 UTC string to the microsecond, and the client as its IP
     * address and user agent.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'occurred_at'       => $this->occurredAt->utc()->format('Y-m-d\TH:i:s.u\Z'),
            'guard'             => $this->guard,
            'method'            => $this->method,
            'ip'                => $this->client->ip,
            'user_agent'        => $this->client->userAgent,
            'identity_type'     => $this->identityType,
            'identity_id'       => $this->identityId,
            'principal_type'    => $this->principalType,
            'principal_id'      => $this->principalId,
            'tenant_type'       => $this->tenantType,
            'tenant_id'         => $this->tenantId,
            'session_id'        => $this->sessionId,
            'credential_id'     => $this->credentialId,
            'scopes'            => $this->scopes,
            'connection_id'     => $this->connectionId,
            'request_reference' => $this->requestReference,
        ];
    }

    /**
     * What an Eloquent session row records, read from its attributes without a
     * query: its owner's morph class (`ownerType`) or identifier (`owner`), its
     * principal's morph class (`type`) or identifier (`id`), or its active
     * tenant's identifier (`tenant`); `null` when the row records none or there
     * is no such row.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  'id'|'owner'|'ownerType'|'tenant'|'type'  $part
     * @return ?string
     */
    private static function recordedOn(?Session $session, string $part): ?string
    {
        if (!$session instanceof EloquentSession || !$session instanceof Model) {
            return null;
        }

        [$type, $id] = PrincipalReference::columns($session);

        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession $blank */
        $blank   = $session->newInstance();
        $owner   = $blank->authenticatable();
        $columns = ['ownerType' => $owner->getMorphType(), 'owner' => $owner->getForeignKeyName(), 'type' => $type, 'id' => $id, 'tenant' => $session->getTenantIdName()];

        return IdentifierCoercion::stringify($session->getAttributes()[$columns[$part]] ?? null);
    }
}
