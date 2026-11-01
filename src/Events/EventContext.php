<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\ClassMorphViolationException;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Concerns\SerializesLiveModels;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Who and what a package event is about: the guard, the client the request came
 * from, the identity, principal, tenant and session, the sign-in method, and
 * the credential (an API key or a passkey) with the scopes it grants. Every
 * package event carries one, so a single listener on `AuthenticationEvent` can
 * attribute them all the same way.
 *
 * A part the event's flow did not establish is `null`: a failure carries only
 * as much as it got to before it failed, and a session id a token named is kept
 * even when no session row was loaded. An event about the session row itself (a
 * revocation, or a refresh or switch refused on the row's own state before its
 * owner was read) is built with `fromSession`: an identity or principal it does
 * not hold then takes the snapshot of the owner and the principal the row
 * records; sessions record no tenant. Every other event keeps the snapshots of
 * what it holds, so an identity's sign-out everywhere, a pending choice of
 * principal or a refused switch to another principal names no principal, even
 * when it carries a session.
 *
 * Everything but the four models is the snapshot, fixed when the context is
 * built: when (`occurredAt`), the guard, the client, the method, the
 * credential's id and scopes, the morph class (an Eloquent model's morph class,
 * else the class name, which also stands for a model an enforced morph map
 * leaves out) and identifier of the identity, the principal and the tenant, and
 * the session's identifier. It is the record an audit sink keeps, and
 * `toArray()` gives it as scalars. The models are a convenience: a synchronous
 * listener gets the instances the package holds, and after a queue each
 * Eloquent model is fetched again in its state then (with the relations it had
 * loaded), or is `null` once its row is gone; a part that is not an Eloquent
 * model does not cross a queue and is `null` after one. A queued model is
 * current state, not evidence of what was authorised. `scopes` is `null` for a
 * human identity's session, which no credential limits, and the list the
 * credential grants otherwise (`[]` grants none). Never carries a token, a key,
 * a digest, a password or any other secret.
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

    /** @var ?string The principal's morph class (an Eloquent model's morph class, or its class name), as a session records it, when the event was built. */
    public ?string $principalMorphClass;

    /** @var ?string The principal's identifier when the event was built. */
    public ?string $principalId;

    /** @var ?string The tenant's morph class (an Eloquent model's morph class, or its class name) when the event was built. */
    public ?string $tenantMorphClass;

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
     */
    public function __construct(

        /** Name of the guard the event is about; `null` only for a session that records none, or a verification link refused before its guard could be trusted. */
        public ?string $guard,

        /** Client of the request being served (in a queue job or a console command, that process's request). */
        public ClientContext $client,

        /** Identity the event is about, if known. */
        public ?Identity $identity = null,

        /** Principal the identity acts as, if known. */
        public ?Principal $principal = null,

        /** Tenant the principal acts within, if known and there is one. */
        public ?Tenant $tenant = null,

        /** The session, if one was loaded. */
        public ?Session $session = null,

        /** Name of the sign-in method; for a session's events, the method it records. */
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
    ) {
        $recorded = $fromSession ? $session : null;

        $this->occurredAt          = CarbonImmutable::now();
        $this->identityMorphClass  = $identity  === null ? self::recordedOn($recorded, 'ownerType') : self::morphClassOf($identity);
        $this->identityId          = $identity  === null ? self::recordedOn($recorded, 'owner') : IdentifierCoercion::stringify($identity->getAuthIdentifier());
        $this->principalMorphClass = $principal === null ? self::recordedOn($recorded, 'type') : self::morphClassOf($principal);
        $this->principalId         = $principal === null ? self::recordedOn($recorded, 'id') : PrincipalReference::id($principal);
        $this->tenantMorphClass    = $tenant    === null ? null : self::morphClassOf($tenant);
        $this->tenantId            = IdentifierCoercion::stringify($tenant?->getTenantIdentifier());
        $this->sessionId           = $session === null ? $sessionId : IdentifierCoercion::stringify($session->getSessionIdentifier());
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
            'tenant_morph_class'    => $this->tenantMorphClass,
            'tenant_id'             => $this->tenantId,
            'session_id'            => $this->sessionId,
            'credential_id'         => $this->credentialId,
            'scopes'                => $this->scopes,
        ];
    }

    /**
     * The morph class an identity, principal or tenant is recorded by: an
     * Eloquent model's morph class, any other object's class name.
     *
     * A model the morph map leaves out under `Relation::enforceMorphMap()` is
     * recorded by its class name: a tenant reached through a plain relation
     * never needed an alias, and the snapshot must not fail the flow it
     * reports.
     *
     * @param  object  $subject
     * @return string
     */
    private static function morphClassOf(object $subject): string
    {
        try {
            return $subject instanceof Model ? $subject->getMorphClass() : $subject::class;
        } catch (ClassMorphViolationException) {
            return $subject::class;
        }
    }

    /**
     * What an Eloquent session row records, read from its attributes without a
     * query: its owner's morph class (`ownerType`) or identifier (`owner`), or
     * its principal's morph class (`type`) or identifier (`id`); `null` when
     * the row records none or there is no such row.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  'id'|'owner'|'ownerType'|'type'  $part
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
        $columns = ['ownerType' => $owner->getMorphType(), 'owner' => $owner->getForeignKeyName(), 'type' => $type, 'id' => $id];

        return IdentifierCoercion::stringify($session->getAttributes()[$columns[$part]] ?? null);
    }
}
