<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Writes a session the session service starts: always a new session, which
 * replaces the existing session a client proved it holds, if any, and the first
 * token pair.
 *
 * Each runs in one transaction on the session's connection. The session is
 * written first (after the revocation of the session it replaces) and the
 * tokens are issued after it, inside the transaction, so a cancelled insert or
 * any failure while issuing (signing, randomness, an identifier that cannot be
 * read) rolls every write back: no session is left without a client that holds
 * its refresh token, and no session is revoked for a replacement that was not
 * written. Only the digest of the new rotation id is stored. Every time is the
 * one `$now` of the sign-in, formatted with the session model's own date
 * format.
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
     */
    public function __construct(

        /** Name of the guard whose sessions the writer writes. */
        private string $guard,

        /** The guard's token service, which issues the pair. */
        private JwtTokenService $tokens,

        /** Resolver for the session's own connection. */
        private ConnectionResolverInterface $connections,
    ) {}

    /**
     * Create a session of the configured model for the admitted sign-in and
     * issue its first pair.
     *
     * The session records its owner (the identity, which must be an Eloquent
     * model), the principal, the guard, the sign-in method and the type of
     * identifier it used, the client's name and platform, the IP address and
     * user agent of the client the sign-in came from (`$origin`) as its
     * creation, the context's client and the sign-in as its last use (so
     * recording the use when the guard binds it writes nothing more), the
     * digest of a new rotation id, and both deadlines: the absolute one capped
     * at the context's deadline, if it gives one, and `null` when neither it
     * nor the application sets one. A context whose deadline has already passed
     * is an `InvalidArgumentException`: establishment refuses such a sign-in
     * first.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $origin
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function create(
        Admitted $admitted,
        string $method,
        ?string $identifierType,
        SignInContext $context,
        TokenLifetimes $lifetimes,
        CarbonImmutable $now,
        ClientContext $origin,
    ): SignedInSession {
        $rotationId = RefreshTokenHasher::generate();
        $session    = $this->newSession($admitted, $method, $identifierType, $context, $origin);

        $session->forceFill(self::sessionState($session, $rotationId, $context, $lifetimes, $now));

        return $session->getConnection()->transaction(function () use ($session, $admitted, $method, $rotationId, $now): SignedInSession {

            self::insert($session);

            return $this->issue($session, $admitted, $method, $rotationId, $now);
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
     * digest the client proved, is not revoked, and records the owner,
     * principal and guard it was proven for; any concurrent refresh, revocation
     * or change makes it affect no row, and then nothing is written. The
     * revocation, the new session and its pair are one transaction, so a
     * cancelled insert or a failure while issuing leaves the proven session as
     * it was.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $origin
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function replace(
        Admitted $admitted,
        string $method,
        ?string $identifierType,
        SignInContext $context,
        TokenLifetimes $lifetimes,
        CarbonImmutable $now,
        ClientContext $origin,
    ): ?SignedInSession {
        $previous   = self::provenSession($admitted);
        $rotationId = RefreshTokenHasher::generate();
        $described  = new SignInContext(
            $context->client,
            $context->clientName ?? self::recorded($previous, $previous->getClientNameName()),
            $context->platform   ?? self::recorded($previous, $previous->getPlatformName()),
            notAfter: $context->notAfter,
        );
        $session = $this->newSession($admitted, $method, $identifierType, $described, $origin);

        $session->forceFill(self::sessionState($session, $rotationId, $described, $lifetimes, $now));

        $revoked = RefreshRotationStore::revocation($previous, RevocationReason::SUPERSEDED, $now);

        return $session->getConnection()->transaction(function () use ($previous, $revoked, $session, $admitted, $method, $rotationId, $now): ?SignedInSession {

            if (!$this->swap($previous, $revoked)) {
                return null;
            }

            self::insert($session);

            return $this->issue($session, $admitted, $method, $rotationId, $now);
        });
    }

    /**
     * A new, unsaved session of the configured model for the admitted sign-in,
     * created from the origin's client, with the context's client name and
     * platform, and none of the state it starts with (`sessionState()`) yet.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $origin
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function newSession(Admitted $admitted, string $method, ?string $identifierType, SignInContext $context, ClientContext $origin): EloquentSession&Model
    {
        $session  = SessionLookup::model();
        $identity = self::eloquentIdentity($admitted);
        $owner    = $session->authenticatable();

        [$principalType, $principalId] = PrincipalReference::columns($session);

        return $session->forceFill([
            $owner->getMorphType()                  => $identity->getMorphClass(),
            $owner->getForeignKeyName()             => IdentifierCoercion::stringify($identity->getKey()),
            $principalType                          => PrincipalReference::type($admitted->principal),
            $principalId                            => PrincipalReference::id($admitted->principal),
            $session->getGuardName()                => $this->guard,
            $session->getSignInMethodName()         => $method,
            $session->getSignInIdentifierTypeName() => $identifierType,
            $session->getClientNameName()           => $context->clientName,
            $session->getPlatformName()             => $context->platform,
            $session->getCreatedIpName()            => $origin->ip,
            $session->getCreatedUserAgentName()     => $origin->userAgent,
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
     * The admitted identity, which must be an Eloquent model to own a session.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     */
    private static function eloquentIdentity(Admitted $admitted): Identity&Model
    {
        $identity = $admitted->identity;

        if (!$identity instanceof Model) {
            throw new \LogicException(sprintf('The session service can only create a session for an Eloquent identity; %s is not a model.', $identity::class));
        }

        return $identity;
    }

    /**
     * The state of a session that starts at `$now`: the client as its last use,
     * the digest of the new rotation id with no previous one, the start itself,
     * and both deadlines, the absolute one the earlier of the application's
     * limit and the context's deadline, either alone, or none.
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
     * Apply the values to the proven session with one compare-and-swap on its
     * own connection: only while the row still holds the digest, owner,
     * principal and guard it was loaded with, exactly as stored, and is not
     * revoked. The values are mirrored on the in-memory session as persisted
     * state when the swap changed the row. Returns whether it did.
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
