<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;

/**
 * A queued job that binds an identity on the `api` guard and leaves it bound,
 * as a job that acts on a user's behalf does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignInOnGuardJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /**
     * Constructor.
     *
     * @param  int  $identityId
     */
    public function __construct(

        /** Key of the identity the job acts as. */
        public int $identityId,
    ) {}

    /**
     * Bind the identity, as its own principal, on the `api` guard.
     *
     * @return void
     */
    public function handle(): void
    {
        $guard    = Auth::manager()->guard('api');
        $identity = IntegrationIdentity::query()->findOrFail($this->identityId);

        assert($guard instanceof JwtGuard);

        $guard->login($identity, $identity);
    }
}
