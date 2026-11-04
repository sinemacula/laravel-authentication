<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessionProofs;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;

/**
 * The session service's lookups of one session, of one principal, and of an
 * active session's proofs and first factor, which `ActiveSessions`,
 * `PendingEvaluation` and `ActiveSessionProofs` carry out, as the session list
 * and `principals()` do.
 *
 * They are delegations with no state of their own; they sit in a trait only so
 * the service stays within the number of methods one class may declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait LooksUpSessions
{
    /**
     * One of the identity's active sessions, of any guard, by its identifier,
     * for a "where you are signed in" detail or before revoking it: the same
     * summary the session list gives, without its digests, revocation or
     * principal, marked when it is the session this guard is authenticated with
     * for the request. Read on the write connection through the identity's
     * `sessions()` relation, so another identity's session is not found. `null`
     * when the session is not the identity's, is not active (pending, revoked,
     * or past a deadline) or does not exist, without saying which; an
     * identifier that cannot be a key of the session model is not queried.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $sessionId
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SessionSummary
     *
     * @throws \LogicException
     */
    public function session(Identity $identity, mixed $sessionId): ?SessionSummary
    {
        return ActiveSessions::find($identity, $sessionId, $this->binding->session());
    }

    /**
     * One of the principals the identity may use the application as, by its
     * principal identifier, for a switch destination or a "your memberships"
     * detail: the one `principals()` would list with that identifier, judged by
     * the same reads and checks (the identity's `principals()` on the write
     * connection, or the resolver's default, each active, in an active tenant
     * or none, and allowed to use the application by `ApplicationAccess`), and
     * with an identifier type the application policy must admit the identity
     * with it first. `null` when the principal is not the identity's, is not
     * admitted, or two of the identity's principals share the identifier,
     * without saying which. A switch destination is checked again by the
     * switch. A principal found among the identity's `principals()` that uses
     * `ActsAsPrincipal` holds its tenant, loaded on the write connection, so
     * reading `getTenant()` on it costs no further query and never lazy-loads,
     * even under Eloquent strict mode; the resolver's default is returned as
     * the resolver gave it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $principalId
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principal(Identity $identity, mixed $principalId, ?string $identifierType = null): ?Principal
    {
        return $this->evaluation->principal($identity, $principalId, $identifierType);
    }

    /**
     * The counting proofs of one of this guard's live, active sessions of a
     * person, by its identifier, for a factor package's proof store, a
     * requirement checker or a confirmation that reads what a session proved:
     * newest first by time and then by id, only those made at or after `$since`
     * when it is given and of the given kinds when they are, at most `$limit`
     * of them (1 to `RequirementSubject::MAX_LIMIT`, an
     * `InvalidArgumentException` otherwise, before anything is read), exactly
     * as `PendingSession::proofs()` reads a pending session's. Counting proofs
     * are those not voided, and a further factor or recovery code only when
     * accepted.
     *
     * `[]` when the session is not one this guard may answer for, without
     * saying why: an identifier that cannot be a key of the session model (no
     * query), one that names no session, or a session of another guard, a
     * revoked, pending (read through its `PendingSession` instead) or ended
     * one, or a machine's. The proofs are read bound to the session as stored,
     * whichever session holds the key now, so another identity's or
     * application's proof under the key never counts. No identity is checked:
     * which sessions a caller may ask about is the application's to decide.
     *
     * Outside a transaction on the session model's connection the session and
     * its proofs are read on the write connection and nothing is locked. Inside
     * one, the session's row is locked until the transaction ends and the
     * proofs are read current, so whatever the transaction read before, a
     * step-up committed before the call is returned and a proof voided before
     * it never is (at PostgreSQL's REPEATABLE READ the lock fails to serialise
     * instead, for the whole transaction to be retried). It writes and reports
     * nothing.
     *
     * @param  mixed  $sessionId
     * @param  ?\Carbon\CarbonImmutable  $since
     * @param  ?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>  $kinds
     * @param  int  $limit
     * @return list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @phpstan-impure
     */
    public function proofs(mixed $sessionId, ?CarbonImmutable $since = null, ?array $kinds = null, int $limit = 50): array
    {
        return ActiveSessionProofs::query($this->context->name(), $sessionId, $since, $kinds, $limit);
    }

    /**
     * The first factor one of this guard's live, active sessions of a person
     * signed in with, by its identifier: its oldest counting first-factor
     * proof. `null` when the session is not one this guard may answer for, as
     * `proofs()` decides, without saying why, and when that proof no longer
     * counts. Read, and locked inside a transaction, as `proofs()` is.
     *
     * @param  mixed  $sessionId
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @phpstan-impure
     */
    public function firstFactor(mixed $sessionId): ?RecordedProof
    {
        return ActiveSessionProofs::firstFactor($this->context->name(), $sessionId);
    }
}
