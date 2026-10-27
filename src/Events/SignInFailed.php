<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * Dispatched when a sign-in fails, through `attempt()` or the session service,
 * with a machine-readable reason. Fired after Laravel's `Failed`.
 *
 * Carries as much context as the sign-in established before it failed: the
 * identity only once its sign-in method verified it, so a wrong password or an
 * unknown identifier carries none, and the principal and tenant only once they
 * were resolved. The identifier is the one the input named, as given. Never a
 * password, a code, a token or any other secret.
 *
 * It says why a sign-in failed even where the client is not told: a refusal by
 * the account's own limit is `account_rate_limited` here, with the wait, while
 * the sign-in's result says `invalid_credentials`, so listeners (lockout
 * notices, a SIEM) can tell a locked account from a wrong password.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignInFailed
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  ?string  $method
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason  $reason
     * @param  ?string  $identifier
     * @param  ?int  $retryAfter
     */
    public function __construct(

        /** Name of the guard the sign-in was for. */
        public string $guard,

        /** Identity the sign-in method verified, if it got that far. */
        public ?Identity $identity,

        /** Principal the sign-in resolved, if it got that far. */
        public ?Principal $principal,

        /** Tenant the principal acts within, if it got that far and there is one. */
        public ?Tenant $tenant,

        /** Device the sign-in concerned, if any. */
        public ?Device $device,

        /** Name of the sign-in method, when known. */
        public ?string $method,

        /** Client the sign-in came from. */
        public ClientContext $client,

        /** Machine-readable failure reason. */
        public SignInFailureReason $reason,

        /** Identifier the input named, as given, if any. */
        public ?string $identifier = null,

        /** Seconds until another attempt may be made, for `rate_limited` and `account_rate_limited` only. */
        public ?int $retryAfter = null,
    ) {}
}
