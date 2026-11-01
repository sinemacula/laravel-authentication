<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Writes a session the session service starts: always a new session, active
 * with its first token pair (replacing the existing session a client proved it
 * holds, if any), or pending with its pending credential (recording the session
 * the client proved, which its first activation supersedes), and its first
 * proof and provenance.
 *
 * Each runs in one transaction on the session's connection. The session is
 * written first (after the revocation of the session it replaces), then the
 * sign-in's first-factor proof, then its provenance when an external provider
 * established it, each after deleting what an earlier session holding the same
 * key left, and the tokens are issued after them, inside the transaction, so a
 * cancelled insert or any failure while issuing (signing, randomness, an
 * identifier that cannot be read) rolls every write back: no session is left
 * without a client that holds its refresh token or pending credential, or
 * without the proof its tokens are derived from, and no session is revoked for
 * a replacement that was not written. Only the digest of the new rotation id,
 * or of the pending credential's secret, is stored. Every session time is the
 * one `$now` of the sign-in, formatted with the session model's own date
 * format; each proof keeps its own time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionWriter
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  ?string  $policyVersion
     */
    public function __construct(

        /** Name of the guard whose sessions the writer writes. */
        private string $guard,

        /** The guard's token service, which issues the pair. */
        private JwtTokenService $tokens,

        /** Resolver for the session's own connection. */
        private ConnectionResolverInterface $connections,

        /** The tenant authentication policy version the sessions it writes were checked against, if any. */
        private ?string $policyVersion = null,
    ) {}

    /**
     * The same writer, for sessions checked against the tenant authentication
     * policy at the version given (`null` for none), which they record.
     *
     * @param  ?string  $version
     * @return self
     */
    public function underTenantPolicy(?string $version): self
    {
        return new self($this->guard, $this->tokens, $this->connections, $version);
    }

    /**
     * Create a session of the configured model for the admitted sign-in and
     * issue its first pair.
     *
     * The session records that it is active, a new generation, its owner (the
     * identity, which must be an Eloquent model), the principal and the active
     * tenant, the guard, the sign-in method (the proof's) and the type of
     * identifier it used, the client's name and platform, the IP address and
     * user agent of the client the sign-in came from (`$origin`) as its
     * creation, the context's client and the sign-in as its last use (so
     * recording the use when the guard binds it writes nothing more), the
     * digest of a new rotation id, and both deadlines: the absolute one capped
     * at the context's deadline, if it gives one, and `null` when neither it
     * nor the application sets one; then the sign-in's proofs and provenance
     * (`$proof`). A context whose deadline has already passed is an
     * `InvalidArgumentException`: establishment refuses such a sign-in first.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $origin
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function create(
        Admitted $admitted,
        ?string $identifierType,
        SignInContext $context,
        TokenLifetimes $lifetimes,
        CarbonImmutable $now,
        ClientContext $origin,
        SignInProof $proof,
    ): SignedInSession {
        $rotationId = RefreshTokenHasher::generate();
        $session    = $this->newSession($admitted->identity, $admitted->principal, $admitted->tenant, $proof->method, $identifierType, $context, $origin);

        $session->forceFill(self::sessionState($session, $rotationId, $context, $lifetimes, $now));

        return $session->getConnection()->transaction(function () use ($session, $admitted, $proof, $rotationId, $now): SignedInSession {

            self::insert($session);

            $this->record($session, $proof);

            return $this->issue($session, $admitted, $proof->method, $rotationId, $now);
        });
    }

    /**
     * Replace the session the client proved it holds, the admitted sign-in's
     * session, with a new one for the sign-in, and issue the new session's
     * first pair; `null` when the proven session changed after it was proven,
     * so it cannot be replaced.
     *
     * Every sign-in is a new session, so the new session is written exactly as
     * `create()` writes one, the context's deadline included, except that a
     * client name or platform the context does not give is the proven session's
     * (the client proved it is the same one). The proven session is revoked
     * first, with the reason `superseded` and both of its digests forgotten, by
     * one compare-and-swap that applies only while the row still holds the
     * digest the client proved, is active and not revoked, and records the
     * owner, principal and guard it was proven for; any concurrent refresh,
     * revocation, return to pending or change makes it affect no row, and then
     * nothing is written. The revocation, the new session and its pair are one
     * transaction, so a cancelled insert or a failure while issuing leaves the
     * proven session as it was. The new session records only its own sign-in's
     * proofs: the replaced session's stay with it.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $origin
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function replace(
        Admitted $admitted,
        ?string $identifierType,
        SignInContext $context,
        TokenLifetimes $lifetimes,
        CarbonImmutable $now,
        ClientContext $origin,
        SignInProof $proof,
    ): ?SignedInSession {
        $previous   = self::provenSession($admitted);
        $rotationId = RefreshTokenHasher::generate();
        $described  = new SignInContext(
            $context->client,
            $context->clientName ?? self::recorded($previous, $previous->getClientNameName()),
            $context->platform   ?? self::recorded($previous, $previous->getPlatformName()),
            notAfter: $context->notAfter,
        );
        $session = $this->newSession($admitted->identity, $admitted->principal, $admitted->tenant, $proof->method, $identifierType, $described, $origin);

        $session->forceFill(self::sessionState($session, $rotationId, $described, $lifetimes, $now));

        $revoked = RefreshRotationStore::revocation($previous, RevocationReason::SUPERSEDED, $now);

        return $session->getConnection()->transaction(function () use ($previous, $revoked, $session, $admitted, $proof, $rotationId, $now): ?SignedInSession {

            if (!$this->swap($previous, $revoked)) {
                return null;
            }

            self::insert($session);

            $this->record($session, $proof);

            return $this->issue($session, $admitted, $proof->method, $rotationId, $now);
        });
    }

    /**
     * Create a pending session of the configured model for a sign-in that still
     * waits on requirements, and return it with its pending credential.
     *
     * The session is written as `create()` writes one (its owner, the principal
     * and active tenant when one is selected, the guard, method, identifier
     * type and client, a new generation, the start and both deadlines), except
     * that it is pending: it records what it waits on, in order, the digest of
     * a new secret, no refresh credential, the session the client proved it
     * holds and the digest it was proven against (its first activation
     * supersedes that session only while it is unchanged), and the windows of
     * the attempt-limit slots the sign-in holds until then. Its idle deadline
     * is the pending credential's expiry: `$ttlSeconds` from `$now`, never past
     * its absolute deadline, so an expired pending session has ended as any
     * session ends. The first factor's proof and provenance are recorded with
     * it, so they carry to the active session unchanged.
     *
     * The credential is `<session key>.<secret>`; only the secret's digest is
     * stored, and the credential is never written anywhere else.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSessionDraft  $draft
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $ttlSeconds
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function createPending(PendingSessionDraft $draft, SignInContext $context, TokenLifetimes $lifetimes, CarbonImmutable $now, int $ttlSeconds): array
    {
        $secret  = RefreshTokenHasher::generate();
        $proof   = $draft->proof;
        $windows = $draft->attemptWindows;
        $session = $this->newSession($draft->identity, $draft->principal, $draft->tenant, $proof->method, $draft->identifierType, $context, $context->client);

        $session->forceFill(self::pendingState($session, $secret, $context, $lifetimes, $now, $draft->proven, $ttlSeconds));

        PendingState::fill($session, [
            $session->getRequiresName()       => PendingState::requires($draft->requires),
            $session->getAttemptWindowsName() => $windows === null ? null : json_encode($windows, JSON_THROW_ON_ERROR),
        ]);

        return $session->getConnection()->transaction(function () use ($session, $proof, $secret): array {

            self::insert($session);

            $this->record($session, $proof);

            return [$session, IdentifierCoercion::stringify($session->getSessionIdentifier()) . '.' . $secret];
        });
    }

    /**
     * A new, unsaved session of the configured model for the sign-in, created
     * from the origin's client, with the context's client name and platform,
     * the principal (`null` while a choice is outstanding), the active tenant's
     * id (`null` for none) and the tenant policy version it was checked
     * against, and none of the state it starts with (`sessionState()`,
     * `pendingState()`) yet.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $origin
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function newSession(
        Identity $identity,
        ?Principal $principal,
        ?Tenant $tenant,
        string $method,
        ?string $identifierType,
        SignInContext $context,
        ClientContext $origin,
    ): EloquentSession&Model {
        $session = SessionLookup::model();
        $owner   = self::eloquentIdentity($identity);

        [$principalType, $principalId] = PrincipalReference::columns($session);

        return $session->forceFill([
            $session->authenticatable()->getMorphType()      => $owner->getMorphClass(),
            $session->authenticatable()->getForeignKeyName() => IdentifierCoercion::stringify($owner->getKey()),
            $principalType                                   => $principal === null ? null : PrincipalReference::type($principal),
            $principalId                                     => $principal === null ? null : PrincipalReference::id($principal),
            $session->getTenantIdName()                      => IdentifierCoercion::stringify($tenant?->getTenantIdentifier()),
            $session->getTenantPolicyVersionName()           => $this->policyVersion,
            $session->getGuardName()                         => $this->guard,
            $session->getSignInMethodName()                  => $method,
            $session->getSignInIdentifierTypeName()          => $identifierType,
            $session->getClientNameName()                    => $context->clientName,
            $session->getPlatformName()                      => $context->platform,
            $session->getCreatedIpName()                     => $origin->ip,
            $session->getCreatedUserAgentName()              => $origin->userAgent,
        ]);
    }

    /**
     * The session the admitted sign-in is on, which the client proved it holds
     * and which must be an Eloquent session to be replaced.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \LogicException
     */
    private static function provenSession(Admitted $admitted): EloquentSession&Model
    {
        $session = $admitted->session;

        if (!$session instanceof EloquentSession || !$session instanceof Model) {
            throw new \LogicException('The session service can only replace an Eloquent session the client proved it holds.');
        }

        return $session;
    }

    /**
     * Insert the new session, or throw when a model event cancelled the insert:
     * Eloquent reports that only by returning `false`, after the key is already
     * set, so carrying on would issue a pair for a session that was never
     * written and commit the revocation of the session it replaces.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     *
     * @throws \LogicException
     */
    private static function insert(EloquentSession&Model $session): void
    {
        if (!$session->save()) {
            throw new \LogicException(sprintf('%s was not saved: a model event cancelled the new session, so the sign-in wrote nothing.', $session::class));
        }
    }

    /**
     * A description the session recorded, as the model reads it: its text, or
     * `null` when it recorded none or it is not loaded.
     *
     * Read through the model's casts and accessors rather than as stored, since
     * the new session writes it through its casts and mutators again: a stored
     * value would be cast twice (an encrypted name encrypted a second time).
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  string  $column
     * @return ?string
     */
    private static function recorded(Model $session, string $column): ?string
    {
        $value = array_key_exists($column, $session->getAttributes()) ? $session->getAttribute($column) : null;

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * The identity, which must be an Eloquent model to own a session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     */
    private static function eloquentIdentity(Identity $identity): Identity&Model
    {
        if (!$identity instanceof Model) {
            throw new \LogicException(sprintf('The session service can only create a session for an Eloquent identity; %s is not a model.', $identity::class));
        }

        return $identity;
    }

    /**
     * The state of a session that starts active at `$now`: a generation of its
     * own, the client as its last use, the digest of the new rotation id with
     * no previous one, the start itself, and both deadlines, the absolute one
     * the earlier of the application's limit and the context's deadline, either
     * alone, or none.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $rotationId
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function sessionState(
        EloquentSession&Model $session,
        #[\SensitiveParameter] string $rotationId,
        SignInContext $context,
        TokenLifetimes $lifetimes,
        CarbonImmutable $now,
    ): array {
        if ($context->hasPassedDeadline($now)) {
            throw new \InvalidArgumentException('Cannot start a session whose deadline is not after its start.');
        }

        $absolute = $lifetimes->absoluteDeadline($now, $context->notAfter);

        return [
            $session->getStatusName()             => SessionStatus::ACTIVE->value,
            $session->getGenerationName()         => Str::uuid7()->toString(),
            $session->getLastUsedAtName()         => $session->fromDateTime($now),
            $session->getLastUsedIpName()         => $context->client->ip,
            $session->getLastUsedUserAgentName()  => $context->client->userAgent,
            $session->getRefreshKeyName()         => RefreshTokenHasher::hash($rotationId),
            $session->getPreviousRefreshKeyName() => null,
            $session->getRefreshRotatedAtName()   => null,
            $session->getSignedInAtName()         => $session->fromDateTime($now),
            $session->getIdleExpiresAtName()      => $session->fromDateTime($lifetimes->idleDeadline($now, $absolute)),
            $session->getAbsoluteExpiresAtName()  => $session->fromDateTime($absolute),
        ];
    }

    /**
     * The state of a session that starts pending at `$now`: a generation of its
     * own, the client as its last use, no refresh credential, the digest of the
     * pending credential's secret, the session the client proved and the digest
     * it was proven against, the start itself, the absolute deadline as an
     * active session's, and the pending credential's expiry as the idle
     * deadline, never past the absolute one.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $secret
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $proven
     * @param  int  $ttlSeconds
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function pendingState(
        EloquentSession&Model $session,
        #[\SensitiveParameter] string $secret,
        SignInContext $context,
        TokenLifetimes $lifetimes,
        CarbonImmutable $now,
        ?Session $proven,
        int $ttlSeconds,
    ): array {
        if ($context->hasPassedDeadline($now)) {
            throw new \InvalidArgumentException('Cannot start a session whose deadline is not after its start.');
        }

        $absolute = $lifetimes->absoluteDeadline($now, $context->notAfter);

        return [
            $session->getStatusName()               => SessionStatus::PENDING->value,
            $session->getPendingKeyName()           => RefreshTokenHasher::hash($secret),
            $session->getSupersedesSessionIdName()  => IdentifierCoercion::stringify($proven?->getSessionIdentifier()),
            $session->getSupersedesRefreshKeyName() => $proven?->getRefreshKey(),
            $session->getGenerationName()           => Str::uuid7()->toString(),
            $session->getLastUsedAtName()           => $session->fromDateTime($now),
            $session->getLastUsedIpName()           => $context->client->ip,
            $session->getLastUsedUserAgentName()    => $context->client->userAgent,
            $session->getRefreshKeyName()           => null,
            $session->getPreviousRefreshKeyName()   => null,
            $session->getRefreshRotatedAtName()     => null,
            $session->getSignedInAtName()           => $session->fromDateTime($now),
            $session->getIdleExpiresAtName()        => $session->fromDateTime(PendingState::expiry($now, $ttlSeconds, $absolute)),
            $session->getAbsoluteExpiresAtName()    => $session->fromDateTime($absolute),
        ];
    }

    /**
     * Record the sign-in's proofs on the new session: its first factor, and the
     * provenance of a session an external provider established. Whatever an
     * earlier session whose key the new one reuses left under it is deleted
     * first, so the new session counts only its own sign-in's proofs.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function record(EloquentSession&Model $session, SignInProof $proof): void
    {
        ProofWriter::clear($session);
        ProofWriter::record($session, $this->guard, $proof->firstFactor(), $proof->id);

        if ($proof->provenance === null) {
            return;
        }

        ProofWriter::provenance($session, $proof->provenance);
    }

    /**
     * Apply the values to the proven session with one compare-and-swap on its
     * own connection: only while the row still holds the digest, owner,
     * principal and guard it was loaded with, exactly as stored, is active and
     * is not revoked. The values are mirrored on the in-memory session as
     * persisted state when the swap changed the row. Returns whether it did.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  array<string, mixed>  $values
     * @return bool
     *
     * @imperative
     */
    private function swap(EloquentSession&Model $session, array $values): bool
    {
        $owner  = $session->authenticatable();
        $proven = [];

        $columns = [$session->getRefreshKeyName(), $owner->getMorphType(), $owner->getForeignKeyName(), ...PrincipalReference::columns($session), $session->getGuardName()];

        foreach ($columns as $column) {
            $proven[$column] = $session->getRawOriginal($column);
        }

        $affected = $this->connections
            ->connection($session->getConnectionName())
            ->table($session->getTable())
            ->where($session->getKeyName(), $session->getKey())
            ->where($proven)
            ->where($session->getStatusName(), SessionStatus::ACTIVE->value)
            ->whereNull($session->getRevokedAtName())
            ->update($values);

        if ($affected !== 1) {
            return false;
        }

        $session->forceFill($values)->syncOriginalAttributes(array_keys($values));

        return true;
    }

    /**
     * Issue the session's first pair at `$now`, after the session was written.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  string  $method
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function issue(EloquentSession&Model $session, Admitted $admitted, string $method, #[\SensitiveParameter] string $rotationId, CarbonImmutable $now): SignedInSession
    {
        $tokens = new TokenPair(
            $this->tokens->issueAccessToken($admitted->identity, $admitted->principal, $admitted->tenant, $session, $now),
            $this->tokens->issueRefreshToken($session, $rotationId, $admitted->principal, $now),
        );

        return new SignedInSession($admitted->identity, $admitted->principal, $session, $tokens, $method);
    }
}
