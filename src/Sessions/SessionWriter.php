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
use SineMacula\Laravel\Authentication\Jwt\SessionTokens;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Writes a session the session service starts, active with its first token pair
 * or pending with its pending credential, with its first proof and provenance.
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
     * policy at the version given (`null` for none).
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

            ConnectionGuards::signIn($session->getConnection(), $proof->provenance);

            self::insert($session);

            $this->record($session, $proof);

            return $this->issue($session, $admitted, $proof->method, $rotationId, $now);
        });
    }

    /**
     * Replace the session the client proved it holds with a new one for the
     * sign-in and issue its first pair, or `null` when the proven session
     * changed since.
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

            ConnectionGuards::signIn($session->getConnection(), $proof->provenance);

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
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSessionDraft  $draft
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $ttlSeconds
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: \SineMacula\Laravel\Authentication\Secrets\Secret}
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

        // `#[\SensitiveParameter]` does not cover what a closure captures,
        // which a dump of the trace shows.
        $held = new \SensitiveParameterValue($secret);

        PendingState::fill($session, [
            $session->getRequiresName()       => PendingState::requires($draft->requires),
            $session->getAttemptWindowsName() => $windows === null ? null : json_encode($windows, JSON_THROW_ON_ERROR),
        ]);

        return $session->getConnection()->transaction(function () use ($session, $proof, $held): array {

            ConnectionGuards::signIn($session->getConnection(), $proof->provenance);

            self::insert($session);

            $this->record($session, $proof);

            return [$session, new Secret(IdentifierCoercion::stringify($session->getSessionIdentifier()) . '.' . $held->getValue())];
        });
    }

    /**
     * A new, unsaved session of the configured model for the sign-in, without
     * the state it starts with.
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
     * The session the admitted sign-in is on, which must be an Eloquent session
     * to be replaced.
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
     * Insert the new session, or throw when a model event cancelled the insert.
     *
     * Eloquent reports a cancelled insert only by returning `false`, after the
     * key is set.
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
     * A description the session recorded, read through the model's casts, or
     * `null` when it recorded none or it is not loaded.
     *
     * Read cast, since the new session casts it again on write (an encrypted
     * name would be encrypted twice).
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
     * The state of a session that starts active at `$now`, with every state
     * column set so the new session reads as a loaded row would.
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
            $session->getStatusName()               => SessionStatus::ACTIVE->value,
            $session->getRequiresName()             => null,
            $session->getPendingKeyName()           => null,
            $session->getSupersedesSessionIdName()  => null,
            $session->getSupersedesRefreshKeyName() => null,
            $session->getAttemptWindowsName()       => null,
            $session->getSwitchedAtName()           => null,
            $session->getIssuanceSequenceName()     => 0,
            $session->getGenerationName()           => Str::uuid7()->toString(),
            $session->getLastUsedAtName()           => $session->fromDateTime($now),
            $session->getLastUsedIpName()           => $context->client->ip,
            $session->getLastUsedUserAgentName()    => $context->client->userAgent,
            $session->getRefreshKeyName()           => RefreshTokenHasher::hash($rotationId),
            $session->getPreviousRefreshKeyName()   => null,
            $session->getRefreshRotatedAtName()     => null,
            $session->getSignedInAtName()           => $session->fromDateTime($now),
            $session->getIdleExpiresAtName()        => $session->fromDateTime($lifetimes->idleDeadline($now, $absolute)),
            $session->getAbsoluteExpiresAtName()    => $session->fromDateTime($absolute),
        ];
    }

    /**
     * The state of a session that starts pending at `$now`, idling out when its
     * pending credential expires.
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
            $session->getSwitchedAtName()           => null,
            $session->getIssuanceSequenceName()     => 0,
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
     * Record the sign-in's proofs on the new session, first deleting whatever
     * an earlier session under the same key left.
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
     * own connection; whether the swap changed the row.
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
        $tokens = SessionTokens::pair($this->tokens, $admitted, $session, $rotationId, $now, true);

        return new SignedInSession($admitted->identity, $admitted->principal, $session, $tokens, $method);
    }
}
