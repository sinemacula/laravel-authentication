<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Callers;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Who a request is, as the credential its route authenticates with proves it
 * (`Auth::caller()`): the guard, the credential, the identity, and the
 * principal, active tenant and session the credential holds, with the pending
 * session a pending credential names and the scopes an access credential
 * grants; and whether a session, identity or principal model is the caller's,
 * for an application that scopes what its routes bind to the caller.
 *
 * The scopes are a ceiling for the application to intersect with its own
 * authorisation, never a grant. They are `null` when no credential limits the
 * caller (a human's access token) and for a pending or refresh caller, which is
 * not a general access caller and for which scopes do not apply; `[]` is a
 * credential granting none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Caller
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential  $credential
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  ?list<string>  $scopes
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SessionService  $sessions
     */
    public function __construct(

        /** Name of the guard the credential belongs to. */
        public string $guard,

        /** The credential the caller was read from. */
        public CallerCredential $credential,

        /** The identity the credential proves. */
        public Identity $identity,

        /** The principal the credential acts as, or `null` while a pending session waits for the choice. */
        public ?Principal $principal,

        /** The active tenant, or `null` for none. */
        public ?Tenant $tenant,

        /** The session the credential holds, or `null` for a credential without one (an access-only token, an API key). */
        public ?Session $session,

        /** The pending session a pending credential names, or `null` for any other credential. */
        public ?PendingSession $pending = null,

        /** The scopes the credential grants (a ceiling, never a grant), or `null` when none limits it or scopes do not apply. */
        public ?array $scopes = null,

        /** The session service of the guard, which admits a principal by its id, or `null` for a guard that keeps no sessions. */
        private ?SessionService $sessions = null,
    ) {}

    /**
     * Whether the model is the caller's, judged from the credential and the
     * model as it is given, so look it up on the write connection
     * (`WriteConnection::during()`).
     *
     * A session must be of the caller's guard and owned by its identity and,
     * for a refresh or a pending credential, be the very session the credential
     * proves; an identity must be the caller's; a principal must be the one the
     * caller acts as, one a pending session offers for the choice, or, for a
     * guard that keeps sessions and any other credential, one the caller's
     * identity may use the application as (`principal()` of the guard's session
     * service, with the identifier type its session records, read on the write
     * connection). Any other model is not the caller's.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function owns(Model $model): bool
    {
        return match (true) {
            $model instanceof Session   => $model instanceof EloquentSession && $this->ownsSession($model),
            $model instanceof Identity  => self::isSameIdentity($model, $this->identity),
            $model instanceof Principal => $this->mayActAs($model),
            default                     => false,
        };
    }

    /**
     * Whether the session is the caller's: of its guard, owned by its identity
     * and, for a refresh or a pending credential, the very session the
     * credential proves.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return bool
     */
    private function ownsSession(EloquentSession&Model $session): bool
    {
        return $session->getGuard() === $this->guard
            && SessionOwnership::isOwner($session, $this->identity)
            && ($this->credential === CallerCredential::ACCESS || self::isSameSession($session, $this->session));
    }

    /**
     * Whether the caller may act as the principal: its current principal, one
     * its pending session offers, or, for any other credential, one its
     * identity may use the application as.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function mayActAs(Principal $principal): bool
    {
        if (self::isSamePrincipal($principal, $this->principal)) {
            return true;
        }

        if ($this->pending === null) {

            $admitted = $this->sessions?->principal($this->identity, $principal->getPrincipalIdentifier(), $this->session?->getSignInIdentifierType());

            return self::isSamePrincipal($principal, $admitted);
        }

        $offered = array_filter($this->pending->principals, static fn (Principal $candidate): bool => self::isSamePrincipal($principal, $candidate));

        return $offered !== [];
    }

    /**
     * Whether the two are the same session: the same class with the same
     * identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $other
     * @return bool
     */
    private static function isSameSession(Session $session, ?Session $other): bool
    {
        return $other !== null
            && $session::class === $other::class
            && IdentifierCoercion::matches($session->getSessionIdentifier(), $other->getSessionIdentifier());
    }

    /**
     * Whether the two are the same identity: the same class with the same
     * identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $other
     * @return bool
     */
    private static function isSameIdentity(Identity $identity, Identity $other): bool
    {
        return $identity::class === $other::class
            && IdentifierCoercion::matches($identity->getAuthIdentifier(), $other->getAuthIdentifier());
    }

    /**
     * Whether the two are the same principal: the same class with the same
     * principal identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $other
     * @return bool
     */
    private static function isSamePrincipal(Principal $principal, ?Principal $other): bool
    {
        return $other !== null
            && $principal::class === $other::class
            && IdentifierCoercion::matches($principal->getPrincipalIdentifier(), $other->getPrincipalIdentifier());
    }
}
