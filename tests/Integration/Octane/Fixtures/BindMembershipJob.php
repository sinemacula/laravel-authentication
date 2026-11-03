<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane\Fixtures;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;

/**
 * A queued job that binds a person, as one of its memberships, on the `admin`
 * guard, as a job acting for someone does, and leaves it bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BindMembershipJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /**
     * Constructor.
     *
     * @param  int  $membership
     */
    public function __construct(

        /** Key of the membership the job acts as. */
        public readonly int $membership,
    ) {}

    /**
     * Bind the membership's person as the membership.
     *
     * @return void
     */
    public function handle(): void
    {
        $guard      = Auth::manager()->guard('admin');
        $membership = ChoosingMembership::query()->findOrFail($this->membership);
        $person     = ChoosingMember::query()->findOrFail($membership->identity_id);

        assert($guard instanceof JwtGuard);

        $guard->login($person, $membership);
    }
}
