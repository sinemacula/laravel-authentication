<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\SessionReauthentication;
use SineMacula\Laravel\Authentication\Sessions\SessionStepUp;

/**
 * The session service's step-up and reauthentication methods.
 *
 * Kept in a trait only to hold the service under the per-class method limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ProvesSessions
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionStepUp Steps sessions up with the further factors adapters verified, on the guard's context. */
    private readonly SessionStepUp $stepUps;

    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionReauthentication Reauthenticates sessions with their first factor, on the guard's context. */
    private readonly SessionReauthentication $reauthentications;

    /**
     * Step the session the proof is bound to up and issue it a new access token
     * only.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    public function stepUp(ProofResult $proof, ClientContext $client): AccessTokenResult
    {
        return $this->stepUps->stepUp($proof, $client);
    }

    /**
     * Reauthenticate the session with its identity's first factor and issue it
     * a new access token only.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function reauthenticate(Session $session, string $method, #[\SensitiveParameter] array $input, ClientContext $client): AccessTokenResult
    {
        return $this->reauthentications->reauthenticate($session, $method, $input, $client);
    }
}
