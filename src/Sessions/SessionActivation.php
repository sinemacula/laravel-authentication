<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionActivated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\SessionTokens;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\SwitchFloor;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Activates a pending session whose every requirement is met, under the row
 * lock the operation that met them holds: the pending credential is consumed,
 * the session records the principal and active tenant it activates as and in,
 * and its token pair is issued, in the operation's transaction.
 *
 * The first activation of a sign-in's session is that sign-in's: it supersedes
 * the session the sign-in's client proved it holds, by one compare-and-swap
 * that applies only while that session still holds the refresh digest it was
 * proven against, records the same owner, principal and guard, and is active
 * and not revoked (when it changed, nothing is written, and the caller judges
 * the session again without it, since a factor policy may have waived the
 * factor for it); it forgets the attempt-limit slots it held, handing them up
 * with the activated session (`SignedInSession::$heldSlots`) for the session
 * service to give back once it has bound the session; and it is reported as a
 * sign-in (`SessionRevoked` for the session superseded, then `SessionCreated`
 * and `SignedIn`). The activation of a session that returned to pending moves
 * the floor for its access tokens' issue time (`SwitchFloor`), so no token from
 * before its return is accepted, and is reported as `SessionActivated`. Every
 * report waits for the commit on the session's connection and for the check of
 * the call it is made for (`AdmissionRecheck`), which lets none but a
 * superseded session's run once it ended the session.
 *
 * The activation's write of the locked pending row, made before the pair is
 * issued, is the session's issuance guard, and the pair's proofs are read
 * current after it, so they include every proof the session committed before.
 * The pair is issued at the operation's `$now`, taken before the lock: no token
 * of the session can have committed in between, since an operation that issued
 * one activated the session, and this one, judged under the lock, would then
 * have found it no longer pending; a proof another operation recorded without
 * activating the session is read with the rest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionActivation
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose sessions activate. */
        private GuardContext $context,

        /** The guard's token service, which issues the pair. */
        private JwtTokenService $tokens,

        /** Container the application policy is resolved from. */
        private Container $container,
    ) {}

    /**
     * Activate the locked pending session as the destination's principal in its
     * tenant, recording the tenant policy version it was checked against, for
     * the client acting on it, and issue its pair at `$now`, superseding on a
     * first activation the session its sign-in's client proved it holds, as the
     * caller found it still is. `null`, with nothing written, when that session
     * changed since.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @param  ?string  $policyVersion
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $call
     * @param  \Carbon\CarbonImmutable  $now
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null  $proven
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function activate(
        EloquentSession&Model $session,
        Admitted $destination,
        ?string $policyVersion,
        AdmissionRecheck $call,
        CarbonImmutable $now,
        (EloquentSession&Model)|null $proven = null,
    ): ?SignedInSession {
        [$identity, $principal, $tenant] = [$destination->identity, $destination->principal, $destination->tenant];

        $first      = $session->getRefreshKey() === null;
        $supersedes = $first && $proven !== null;
        $superseded = $supersedes ? $this->supersede($session, $proven, $principal, $now) : null;

        if ($supersedes && $superseded === null) {
            return null;
        }

        $rotationId   = RefreshTokenHasher::generate();
        $reservations = $first ? self::reservations($session) : [];

        $this->write($session, [
            ...self::activeState($session, $principal, $tenant, $rotationId, $first, $call->client, $now, $this->idleDeadline($session, $now)),
            $session->getTenantPolicyVersionName() => $policyVersion,
        ]);

        $tokens = SessionTokens::pair($this->tokens, $destination, $session, $rotationId, $now);

        $method  = (string) $session->getSignInMethod();
        $context = new EventContext($this->context->name(), $call->client, $identity, $principal, $tenant, $session, $method);

        $first
            ? $this->reportSignIn($session, $context, $destination, $superseded, $call)
            : $call->then($session, fn () => $this->context->dispatch(new SessionActivated($context)));

        return new SignedInSession($identity, $principal, $session, $tokens, $method, $reservations);
    }

    /**
     * The columns an activation writes: active, nothing outstanding, the
     * pending credential consumed, a new rotation id's digest with no previous
     * one, the idle deadline restored, the client as its last use, and the
     * principal and active tenant; on the first activation the proven session
     * and the slots forgotten, on a later one the floor moved.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $rotationId
     * @param  bool  $first
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Carbon\CarbonImmutable  $idle
     * @return array<string, mixed>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \LogicException
     */
    private static function activeState(
        EloquentSession&Model $session,
        Principal $principal,
        ?Tenant $tenant,
        #[\SensitiveParameter] string $rotationId,
        bool $first,
        ClientContext $client,
        CarbonImmutable $now,
        CarbonImmutable $idle,
    ): array {
        [$type, $id] = PrincipalReference::columns($session);

        $since = $first ? [
            $session->getAttemptWindowsName()       => null,
            $session->getSupersedesSessionIdName()  => null,
            $session->getSupersedesRefreshKeyName() => null,
        ] : [
            $session->getSwitchedAtName() => $session->fromDateTime(SwitchFloor::after($session->getSwitchedAt(), $now)),
        ];

        return [
            $session->getStatusName()             => SessionStatus::ACTIVE->value,
            $session->getRequiresName()           => null,
            $session->getPendingKeyName()         => null,
            $session->getRefreshKeyName()         => RefreshTokenHasher::hash($rotationId),
            $session->getPreviousRefreshKeyName() => null,
            $session->getRefreshRotatedAtName()   => null,
            $session->getIdleExpiresAtName()      => $session->fromDateTime($idle),
            $session->getLastUsedAtName()         => $session->fromDateTime($now),
            $session->getLastUsedIpName()         => $client->ip,
            $session->getLastUsedUserAgentName()  => $client->userAgent,
            $type                                 => PrincipalReference::type($principal),
            $id                                   => PrincipalReference::id($principal),
            $session->getTenantIdName()           => IdentifierCoercion::stringify($tenant?->getTenantIdentifier()),
            ...$since,
        ];
    }

    /**
     * The idle deadline the session activates with: the application's idle
     * lifetime from `$now`, never past its absolute deadline.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Carbon\CarbonImmutable  $now
     * @return \Carbon\CarbonImmutable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function idleDeadline(EloquentSession&Model $session, CarbonImmutable $now): CarbonImmutable
    {
        return $this->container->make(ApplicationPolicy::class)->lifetimes($this->context->name())->idleDeadline($now, $session->getAbsoluteExpiresAt());
    }

    /**
     * Write the activation on the locked row, where it is still pending with
     * the credential it was found by, and mirror it on the session.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  array<string, mixed>  $values
     * @return void
     *
     * @throws \LogicException
     */
    private function write(EloquentSession&Model $session, array $values): void
    {
        $affected = $session->getConnection()
            ->table($session->getTable())
            ->where($session->getKeyName(), $session->getKey())
            ->where($session->getStatusName(), SessionStatus::PENDING->value)
            ->where($session->getPendingKeyName(), $session->getPendingKey())
            ->update($values);

        $affected === 1 || throw new \LogicException('A pending session changed under the lock its activation holds.');

        PendingState::mirror($session, $values);
    }

    /**
     * Revoke the session the sign-in's client proved it holds as `superseded`,
     * by one compare-and-swap that applies only while it still holds the
     * refresh digest it was proven against, records the same owner and guard
     * and the principal the session activates as, and is active and not
     * revoked; return it when it was, `null` when it changed.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $proven
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \Carbon\CarbonImmutable  $now
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     */
    private function supersede(EloquentSession&Model $session, EloquentSession&Model $proven, Principal $principal, CarbonImmutable $now): (EloquentSession&Model)|null
    {
        $owner = $session->authenticatable();
        $their = $proven->authenticatable();

        [$type, $id] = PrincipalReference::columns($proven);

        $revoked  = RefreshRotationStore::revocation($proven, RevocationReason::SUPERSEDED, $now);
        $affected = $proven->getConnection()
            ->table($proven->getTable())
            ->where($proven->getKeyName(), $proven->getKey())
            ->where([
                $proven->getStatusName()     => SessionStatus::ACTIVE->value,
                $proven->getRefreshKeyName() => $session->getAttribute($session->getSupersedesRefreshKeyName()),
                $proven->getGuardName()      => $this->context->name(),
                $their->getMorphType()       => $session->getAttribute($owner->getMorphType()),
                $their->getForeignKeyName()  => $session->getAttribute($owner->getForeignKeyName()),
                $type                        => PrincipalReference::type($principal),
                $id                          => PrincipalReference::id($principal),
            ])
            ->whereNull($proven->getRevokedAtName())
            ->update($revoked);

        if ($affected !== 1) {
            return null;
        }

        $proven->forceFill($revoked)->syncOriginalAttributes(array_keys($revoked));

        return $proven;
    }

    /**
     * Schedule the reports of a sign-in's first activation, once committed on
     * the session's connection and after the call's check: `SessionRevoked`
     * (`superseded`) for the session it superseded, if any, whatever the check
     * found, then, when it passed, `SessionCreated` and `SignedIn`, in turn, so
     * a listener that throws stops the reports after its own.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $destination
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null  $superseded
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $call
     * @return void
     */
    private function reportSignIn(
        EloquentSession&Model $session,
        EventContext $context,
        Admitted $destination,
        (EloquentSession&Model)|null $superseded,
        AdmissionRecheck $call,
    ): void {
        [$identity, $principal, $tenant] = [$destination->identity, $destination->principal, $destination->tenant];

        $revoked = $superseded === null ? null : new SessionRevoked(
            new EventContext($this->context->name(), $context->client, $identity, $principal, $tenant, $superseded, $superseded->getSignInMethod()),
            RevocationReason::SUPERSEDED,
        );

        if ($revoked !== null) {
            $call->afterCheck($session, fn () => $this->context->dispatch($revoked));
        }

        $call->then($session, function () use ($context): void {

            $this->context->dispatch(new SessionCreated($context));
            $this->context->dispatch(new SignedIn($context, false));
        });
    }

    /**
     * The attempt-limit reservations the sign-in held, as granted reservations
     * to give back once it activates and is bound: one for each it held, with
     * its windows, for the guard's sign-in flow, the identifier type and the IP
     * address the session records (neither the identifier nor the account,
     * which it does not keep), so the limiter gives back exactly the slots
     * taken. None for a sign-in that reserved nothing (one `start()` or
     * `signInExternally()` began).
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return list<\SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation>
     *
     * @throws \JsonException
     * @throws \LogicException
     */
    private static function reservations(EloquentSession&Model $session): array
    {
        $stored  = $session->getAttributes()[$session->getAttemptWindowsName()] ?? null;
        $windows = is_string($stored) ? json_decode($stored, true, flags: JSON_THROW_ON_ERROR) : [];
        $subject = new AttemptSubject(
            (string) $session->getGuard(),
            AttemptFlow::SIGN_IN,
            null,
            $session->getSignInIdentifierType(),
            IdentifierCoercion::stringify($session->getAttribute($session->getCreatedIpName())),
        );

        $windows = is_array($windows) ? array_values(array_filter($windows, is_array(...))) : [];

        return array_map(static fn (array $window): AttemptReservation => new AttemptReservation($subject, null, $window), $windows);
    }
}
