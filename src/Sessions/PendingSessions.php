<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ProofAcceptance;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\SessionDeadlines;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * Acts on the pending sessions of a guard through their pending credentials:
 * reads one for an action, satisfies its further factor with a proof, records
 * the choice of principal, and discards it.
 *
 * A credential is `<session key>.<secret>`. It names a live pending session of
 * the guard only while the session is this guard's, pending, not revoked and
 * not ended (its idle deadline is the credential's expiry), its digest matches
 * the secret (compared in constant time), the guard's provider returns its very
 * owner, and the principal it records, if any, still resolves through the
 * hinted path as that principal of that owner. Anything else is not found,
 * without saying why. The credential is told apart from every other kind by its
 * path: only these operations read it, and none of them reads a token.
 *
 * Satisfying, choosing and discarding lock the session's row and find it again
 * under the lock, so two calls with one credential serialise: the second finds
 * the session changed and fails as `pending_invalid`. Each runs the gate
 * (`PendingEvaluation`) under the lock: the identity, the method, the principal
 * and its tenant are admitted again, and what the session still waits on is
 * judged again, so the session activates, stays pending, or moves on to the
 * choice. A refusal writes nothing (a proof given with it is not stored) and
 * never revokes the session, which waits until its credential expires; only
 * `discard()` ends one early.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingSessions
{
    /** @var int Longest session key a credential may carry, in characters: the identifier columns' length. */
    private const int KEY_MAX_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingEvaluation  $evaluation
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionActivation  $activation
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationWriter  $revocations
     */
    public function __construct(

        /** The context of the guard whose pending sessions are acted on. */
        private GuardContext $context,

        /** The gate a pending session passes each time it is acted on. */
        private PendingEvaluation $evaluation,

        /** Activates a pending session whose every requirement is met. */
        private SessionActivation $activation,

        /** Revokes a discarded pending session and reports it once committed. */
        private RevocationWriter $revocations,
    ) {}

    /**
     * The live pending session the credential names, or `null`; with an action,
     * also `null` when its first outstanding requirement does not allow the
     * action now. The principals to choose from are listed only while the
     * choice is that requirement. Reads only, on the write connection, with no
     * lock.
     *
     * @param  string  $credential
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction  $action
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Sessions\PendingSession
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function pending(#[\SensitiveParameter] string $credential, ?PendingAction $action, CarbonImmutable $now): ?PendingSession
    {
        $found = $this->find($credential, $now, false);

        if ($found === null) {
            return null;
        }

        [$session, $identity, $principal] = $found;

        $requires = $session->getRequires();

        if ($action !== null && !in_array($action, $requires[0]->actions(), true)) {
            return null;
        }

        $tenant     = $principal   === null ? null : TenantAdmission::recorded($principal, $session->getTenantId(), false);
        $principals = $requires[0] === PendingRequirement::PRINCIPAL ? $this->evaluation->principals($identity, $session->getSignInIdentifierType())[0] : [];

        return $this->describe($session, $identity, $principal, $tenant instanceof Tenant ? $tenant : null, $requires, $principals);
    }

    /**
     * Satisfy the pending session's further factor with the proof an adapter
     * verified, in one transaction under the row lock: the further factor must
     * be its first outstanding requirement (`pending_action_not_allowed`); the
     * proof must be accepted for it (see
     * `ProofAcceptance::forPendingSession()`: `proof_invalid`,
     * `proof_binding_mismatch`); the gate admits the identity,
     * the method, and the principal and tenant the session records, if any;
     * then the proof is stored and what the session still waits on is judged
     * again: nothing, and it activates; the further factor still, and it stays
     * pending; or the choice, and it moves on to it, listing the principals. A
     * proof is stored once per call, also when the session stays pending: a
     * verification is single use on the adapter's side.
     *
     * @param  string  $credential
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function satisfy(#[\SensitiveParameter] string $credential, ProofResult $proof, CarbonImmutable $now): Refused|SignInResult
    {
        return $this->atomically(function () use ($credential, $proof, $now): Refused|SignInResult {

            $found = $this->find($credential, $now, true);

            if ($found === null) {
                return new Refused(FailureReason::PENDING_INVALID);
            }

            [$session, $identity, $principal] = $found;

            $admitted = $this->admitted($session, $identity, $principal, PendingRequirement::MFA, $proof, $now);

            if ($admitted instanceof Refused) {
                return $admitted;
            }

            ProofWriter::record($session, $this->context->name(), NewProof::fromResult($proof));

            return $this->settle($session, $identity, $principal, $admitted, $now);
        });
    }

    /**
     * Record the identity's choice of principal on the pending session, and the
     * tenant it is to be active in (the principal's own unless one is named),
     * in one transaction under the row lock: the choice must be its first
     * outstanding requirement (`pending_action_not_allowed`); the gate admits
     * the identity and the method; the principal must be the identity's,
     * resolved through the hinted path as that very one (`principal_mismatch`),
     * and admitted by the application, and the tenant one it may act in and
     * active; then what the session still waits on is judged again: nothing,
     * and it activates as the principal; a further factor (the identity's
     * policy now asks for one), and it records the principal and tenant and
     * waits for it.
     *
     * @param  string  $credential
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $chosen
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $selection
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function choose(#[\SensitiveParameter] string $credential, Principal $chosen, ?TenantSelection $selection, CarbonImmutable $now): Refused|SignInResult
    {
        return $this->atomically(function () use ($credential, $chosen, $selection, $now): Refused|SignInResult {

            $found = $this->find($credential, $now, true);

            if ($found === null) {
                return new Refused(FailureReason::PENDING_INVALID);
            }

            [$session, $identity] = $found;

            $admitted = $this->admitted($session, $identity, null, PendingRequirement::PRINCIPAL, null, $now);
            $chosenAs = $admitted instanceof Refused ? $admitted : $this->chosen($session, $identity, $chosen, $selection);

            if ($chosenAs instanceof Refused) {
                return $chosenAs;
            }

            [$principal, $tenant] = $chosenAs;

            return $this->settle($session, $identity, $principal, $tenant, $now);
        });
    }

    /**
     * End the live pending session the credential names: revoke it as
     * `signed_out`, under the row lock, and report `SessionRevoked` once
     * committed. Returns whether the credential named one, which this call
     * ended.
     *
     * @param  string  $credential
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function discard(#[\SensitiveParameter] string $credential, CarbonImmutable $now): bool
    {
        return SessionLookup::model()->getConnection()->transaction(function () use ($credential, $now): bool {

            $found = $this->find($credential, $now, true);

            if ($found === null) {
                return false;
            }

            [$session, $identity, $principal] = $found;

            $event = new SessionRevoked(
                new EventContext($this->context->name(), $this->context->client(), $identity, $principal, session: $session, method: $session->getSignInMethod()),
                RevocationReason::SIGNED_OUT,
            );

            return $this->revocations->revoke($session, RevocationReason::SIGNED_OUT, $now, fn () => $this->context->dispatch($event));
        });
    }

    /**
     * The tenant the pending session records, admitted again, when the session
     * may be acted on for the requirement: the requirement is its
     * first outstanding one; a proof, when one is given, is accepted for it;
     * the identity is admitted with the identifier type the sign-in used and
     * the method is still allowed; and the principal it records, if any, may
     * still hold it in that tenant. Otherwise why not.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement  $requirement
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Contracts\Tenant|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function admitted(
        EloquentSession&Model $session,
        Identity $identity,
        ?Principal $principal,
        PendingRequirement $requirement,
        ?ProofResult $proof,
        CarbonImmutable $now,
    ): Refused|Tenant|null {
        $refusal = $this->actionRefusal($session, $requirement, $proof, $now)
            ?? $this->evaluation->identityRefusal($identity, $session->getSignInIdentifierType())
            ?? ($this->evaluation->allowsMethod((string) $session->getSignInMethod()) ? null : FailureReason::METHOD_NOT_ALLOWED);

        $tenant = $refusal === null && $principal !== null ? $this->evaluation->recorded($session, $principal) : null;

        return match (true) {
            $refusal !== null                => new Refused($refusal, $identity, $principal, session: $session),
            $tenant instanceof FailureReason => new Refused($tenant, $identity, $principal, session: $session),
            default                          => $tenant,
        };
    }

    /**
     * Why the pending session may not be acted on for the requirement: it is
     * not the first outstanding one, or the proof given is not accepted for
     * it; `null` when it may.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement  $requirement
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    private function actionRefusal(EloquentSession&Model $session, PendingRequirement $requirement, ?ProofResult $proof, CarbonImmutable $now): ?FailureReason
    {
        if ($session->getRequires()[0] !== $requirement) {
            return FailureReason::PENDING_ACTION_NOT_ALLOWED;
        }

        return $proof === null ? null : ProofAcceptance::forPendingSession($proof, $session, $this->context->name(), self::waitingSince($session), $now);
    }

    /**
     * The principal chosen, as the identity's own principal the application
     * admits, with the tenant it is to be active in; or why not.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $chosen
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $selection
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Principal, 1: ?\SineMacula\Laravel\Authentication\Contracts\Tenant}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function chosen(EloquentSession&Model $session, Identity $identity, Principal $chosen, ?TenantSelection $selection): array|Refused
    {
        $principal = $this->evaluation->named($identity, $chosen);

        if ($principal instanceof FailureReason) {
            return new Refused($principal, $identity, session: $session);
        }

        $tenant = $this->evaluation->destination($principal, $selection);

        return $tenant instanceof FailureReason ? new Refused($tenant, $identity, $principal, session: $session) : [$principal, $tenant];
    }

    /**
     * Judge what the admitted pending session still waits on, and act on it:
     * activate it when nothing is outstanding; otherwise keep it pending,
     * writing what it waits on (and the principal and tenant it records) when
     * that changed, and listing the principals to choose from when the choice
     * is now first. A session left with the choice and no principal to choose
     * from is refused with the reason the last was refused, or
     * `principal_unresolved`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function settle(EloquentSession&Model $session, Identity $identity, ?Principal $principal, ?Tenant $tenant, CarbonImmutable $now): Refused|SignInResult
    {
        $proven   = $this->proven($session);
        $client   = self::recorded($session, $session->getClientNameName());
        $platform = self::recorded($session, $session->getPlatformName());
        $owes     = $this->evaluation->owesFactor($identity, (string) $session->getSignInMethod(), self::origin($session), $client, $platform, $proven, $session);
        $requires = PendingEvaluation::requirements($owes, $principal);

        if ($principal !== null && $requires === []) {
            return SignInResult::signedIn($this->activation->activate($session, $identity, $principal, $tenant, $this->context->client(), $now, $proven));
        }

        [$principals, $refusal] = $requires[0] === PendingRequirement::PRINCIPAL ? $this->evaluation->principals($identity, $session->getSignInIdentifierType()) : [[], null];

        if ($requires[0] === PendingRequirement::PRINCIPAL && $principals === []) {
            return new Refused($refusal ?? FailureReason::PRINCIPAL_UNRESOLVED, $identity, session: $session);
        }

        if ($requires !== $session->getRequires()) {
            $this->wait($session, $principal, $tenant, $requires);
        }

        return SignInResult::pending($this->describe($session, $identity, $principal, $tenant, $requires, $principals));
    }

    /**
     * Record what the locked pending session now waits on, and the principal
     * and tenant it records, and mirror it on the session.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>  $requires
     * @return void
     *
     * @throws \JsonException
     */
    private function wait(EloquentSession&Model $session, ?Principal $principal, ?Tenant $tenant, array $requires): void
    {
        [$type, $id] = PrincipalReference::columns($session);

        $values = [
            $session->getRequiresName() => PendingState::requires($requires),
            $type                       => $principal === null ? null : PrincipalReference::type($principal),
            $id                         => $principal === null ? null : PrincipalReference::id($principal),
            $session->getTenantIdName() => IdentifierCoercion::stringify($tenant?->getTenantIdentifier()),
        ];

        $session->getConnection()->table($session->getTable())->where($session->getKeyName(), $session->getKey())->update($values);

        PendingState::mirror($session, $values);
    }

    /**
     * Describe the pending session, with the principals to choose from while
     * the choice is its first requirement.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>  $requires
     * @param  list<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @return \SineMacula\Laravel\Authentication\Sessions\PendingSession
     *
     * @throws \LogicException
     */
    private function describe(EloquentSession&Model $session, Identity $identity, ?Principal $principal, ?Tenant $tenant, array $requires, array $principals): PendingSession
    {
        $expiresAt = $session->getIdleExpiresAt() ?? throw new \LogicException('A pending session the package wrote always records when its credential expires.');

        return new PendingSession(
            $session->getSessionIdentifier(),
            $this->context->name(),
            $identity,
            $principal,
            $tenant,
            $requires,
            (string) $session->getSignInMethod(),
            CarbonImmutable::instance($expiresAt),
            $session,
            $principals,
        );
    }

    /**
     * The live pending session of the guard the credential names, read on the
     * write connection (locked for update when asked), with its owner reloaded
     * through the guard's provider and the principal it records resolved, or
     * `null`. A credential that cannot name one (no key or secret, or a key
     * longer than any the session can have) is rejected without a query.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $credential
     * @param  \Carbon\CarbonImmutable  $now
     * @param  bool  $lock
     * @return ?array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: \SineMacula\Laravel\Authentication\Contracts\Identity, 2: ?\SineMacula\Laravel\Authentication\Contracts\Principal}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function find(#[\SensitiveParameter] string $credential, CarbonImmutable $now, bool $lock): ?array
    {
        [$key, $secret] = [...explode('.', $credential, 2), ''];

        if ($key === '' || $secret === '' || mb_strlen($key) > self::KEY_MAX_LENGTH) {
            return null;
        }

        $session = $lock ? SessionLookup::lock($key) : SessionLookup::find($key);

        if ($session === null || !$this->isLive($session, $secret, $now)) {
            return null;
        }

        $identity  = $this->owner($session);
        $principal = $identity === null ? false : $this->principalOf($session, $identity);

        return $identity === null || $principal === false ? null : [$session, $identity, $principal];
    }

    /**
     * Whether the session is a live pending session of the guard, waiting on
     * something and holding the digest of the secret, read inside
     * `WriteConnection::during()`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $secret
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \LogicException
     */
    private function isLive(EloquentSession&Model $session, #[\SensitiveParameter] string $secret, CarbonImmutable $now): bool
    {
        $guard = $this->context->name();

        return WriteConnection::during($session, static function () use ($session, $secret, $guard, $now): bool {

            if (!RefreshTokenHasher::verify($secret, $session->getPendingKey() ?? '') || $session->getGuard() !== $guard) {
                return false;
            }

            $waiting = $session->getStatus() === SessionStatus::PENDING && $session->getRequires() !== [];

            return $waiting && $session->getRevokedAt() === null && !SessionDeadlines::hasEnded($session, $now);
        });
    }

    /**
     * The session's owner, reloaded through the guard's provider, when it
     * returns that very owner, active or not.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function owner(EloquentSession&Model $session): ?Identity
    {
        $key      = SessionOwnership::ownerKey($session);
        $identity = $key === null ? null : $this->context->provider()->retrieveById($key);

        return $identity instanceof Identity && SessionOwnership::isOwner($session, $identity) ? $identity : null;
    }

    /**
     * The principal the session records, resolved through the hinted path as
     * that very principal, still the owner's: `null` when it records none, and
     * `false` when the one it records no longer resolves so.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return false|\SineMacula\Laravel\Authentication\Contracts\Principal|null
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function principalOf(EloquentSession&Model $session, Identity $identity): false|Principal|null
    {
        $recorded = IdentifierCoercion::stringify($session->getAttribute(PrincipalReference::columns($session)[1]));

        if ($recorded === null) {
            return null;
        }

        $principal = $this->context->resolver()->resolve($identity, $recorded);

        return $principal instanceof Principal && PrincipalReference::isRecordedOn($session, $principal) && PinnedPrincipal::isOwnedBy($principal, $identity)
            ? $principal
            : false;
    }

    /**
     * The session the sign-in's client proved it holds, when it still is that
     * session as proven: of this guard and owner, unrevoked, and holding the
     * refresh digest it was proven against; else `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function proven(EloquentSession&Model $session): (EloquentSession&Model)|null
    {
        $digest = $session->getAttribute($session->getSupersedesRefreshKeyName());
        $proven = is_string($digest) ? SessionLookup::find($session->getAttribute($session->getSupersedesSessionIdName())) : null;

        if ($proven === null) {
            return null;
        }

        $guard = $this->context->name();
        $still = WriteConnection::during($proven, static function () use ($proven, $session, $digest, $guard): bool {

            $unchanged = $proven->getRevokedAt() === null && $proven->getRefreshKey() === $digest;

            return $unchanged && $proven->getGuard() === $guard && SessionOwnership::ownerKey($proven) === SessionOwnership::ownerKey($session);
        });

        return $still ? $proven : null;
    }

    /**
     * When the pending session began waiting for what it waits on now: the
     * later of its start and its last change of context (a return to pending
     * moves it), so no proof made before then satisfies it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \Carbon\CarbonImmutable
     *
     * @throws \LogicException
     */
    private static function waitingSince(EloquentSession&Model $session): CarbonImmutable
    {
        $started  = $session->getSignedInAt()?->getTimestamp() ?? 0;
        $switched = $session->getSwitchedAt()?->getTimestamp() ?? 0;

        return CarbonImmutable::createFromTimestamp(max($started, $switched));
    }

    /**
     * The client the session's sign-in came from.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private static function origin(EloquentSession&Model $session): ClientContext
    {
        return new ClientContext(self::recorded($session, $session->getCreatedIpName()), self::recorded($session, $session->getCreatedUserAgentName()));
    }

    /**
     * A description the session recorded, as the model reads it, or `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  string  $column
     * @return ?string
     */
    private static function recorded(Model $session, string $column): ?string
    {
        $value = $session->getAttribute($column);

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * Run the work in one transaction on the session model's connection,
     * committing what it wrote unless it answers with a refusal, which rolls
     * back everything it wrote, the proof it stored among it; an exception
     * rolls back too, and is thrown on.
     *
     * @param  \Closure(): (\SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult)  $work
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function atomically(\Closure $work): Refused|SignInResult
    {
        $connection = SessionLookup::model()->getConnection();

        $connection->beginTransaction();

        try {
            $outcome = $work();
        } catch (\Throwable $exception) {
            $connection->rollBack();

            throw $exception;
        }

        $outcome instanceof Refused ? $connection->rollBack() : $connection->commit();

        return $outcome;
    }
}
