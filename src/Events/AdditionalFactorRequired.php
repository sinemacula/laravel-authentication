<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * Dispatched when the session service holds a sign-in for a further factor
 * instead of starting its session: the sign-in method proved the identity (or,
 * through `start()`, something outside the guard did), the identity, principal
 * and tenant were admitted, and the additional-factor policy asked for more.
 * From `signIn()` it is the outcome of that sign-in's `Attempting`; from
 * `start()`, which dispatches no `Attempting`, it is the only event. Completing
 * the pending sign-in dispatches `SignedIn`, and discarding it `SignInFailed`
 * with `additional_factor_failed`.
 *
 * Dispatched once the pending sign-in is committed on its connection (the
 * device model's): at once when that connection has no open transaction, after
 * its transaction commits otherwise, and never for a sign-in that is rolled
 * back.
 *
 * Queued listeners get the identity, principal, tenant and device re-fetched
 * from the database, as Laravel's `SerializesModels` does; the method, the
 * client and the expiry are snapshots. Never carries the pending token, a
 * credential or any other secret.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AdditionalFactorRequired
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** Name of the guard the sign-in is for. */
        public string $guard,

        /** Identity the sign-in proved. */
        public Identity $identity,

        /** Principal the session would act as. */
        public Principal $principal,

        /** Tenant the principal acts within, if any. */
        public ?Tenant $tenant,

        /** Device the client proved it holds, which the session would continue on, if any. */
        public ?Device $device,

        /** Name of the sign-in method that proved the identity. */
        public string $method,

        /** Client the sign-in came from. */
        public ClientContext $client,

        /** When the pending sign-in stops being completable. */
        public CarbonImmutable $expiresAt,
    ) {}
}
