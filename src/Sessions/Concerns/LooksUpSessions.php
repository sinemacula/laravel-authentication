<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\SessionRecords\IdentitySessions;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessionProofs;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;

/**
 * The session service's lookups of one session, one session record, one
 * principal, and an active session's proofs.
 *
 * Kept in a trait only to hold the service under the per-class method limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait LooksUpSessions
{
    /**
     * One of the identity's active sessions, of any guard, by its identifier;
     * `null` when it is not found.
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
     * One of the identity's sessions, of any guard and in any state, by its
     * identifier; `null` when the identity has no such session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $sessionId
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \LogicException
     */
    public function sessionRecord(Identity $identity, mixed $sessionId): (EloquentSession&Model)|null
    {
        if (!$identity instanceof HasSessions) {
            throw new \LogicException(sprintf('Only identities that implement %s have sessions to read; %s does not.', HasSessions::class, $identity::class));
        }

        return IdentitySessions::find($identity, $sessionId);
    }

    /**
     * One of the principals `principals()` would list, by its identifier;
     * `null` when it is not found or not admitted.
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
     * The counting proofs of one of this guard's live, active sessions, newest
     * first; `[]` when the session is not one this guard may answer for.
     *
     * @param  mixed  $session
     * @param  ?\Carbon\CarbonInterface  $since
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
    public function proofs(mixed $session, ?CarbonInterface $since = null, ?array $kinds = null, int $limit = 50): array
    {
        return ActiveSessionProofs::query($this->context->name(), $session, $since, $kinds, $limit);
    }

    /**
     * The oldest counting first-factor proof of one of this guard's live,
     * active sessions; `null` when there is none to answer with.
     *
     * @param  mixed  $session
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @phpstan-impure
     */
    public function firstFactor(mixed $session): ?RecordedProof
    {
        return ActiveSessionProofs::firstFactor($this->context->name(), $session);
    }

    /**
     * The external provenance one of this guard's live, active sessions
     * records; `null` when no provider established it.
     *
     * @param  mixed  $session
     * @return ?\SineMacula\Laravel\Authentication\Proofs\Provenance
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @phpstan-impure
     */
    public function provenance(mixed $session): ?Provenance
    {
        return ActiveSessionProofs::provenance($this->context->name(), $session);
    }
}
