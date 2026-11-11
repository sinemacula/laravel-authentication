<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;

/**
 * A queued job that appends the `api` guard's caller to `observed.callers`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReadCallerJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /**
     * Constructor.
     *
     * @param  ?int  $identityId
     */
    public function __construct(

        /** Key of the identity the job binds before reading, if any. */
        public ?int $identityId = null,
    ) {}

    /**
     * Bind the identity, if any, then record the caller's identifier or `null`.
     *
     * @return void
     */
    public function handle(): void
    {
        Auth::shouldUse('api');

        if ($this->identityId !== null) {

            $guard    = Auth::manager()->guard('api');
            $identity = IntegrationIdentity::query()->findOrFail($this->identityId);

            assert($guard instanceof JwtGuard);

            $guard->login($identity, $identity);
        }

        /** @var list<mixed> $observed */
        $observed   = app()->bound('observed.callers') ? app('observed.callers') : [];
        $observed[] = Auth::caller()?->identity->getAuthIdentifier();

        app()->instance('observed.callers', $observed);
    }
}
