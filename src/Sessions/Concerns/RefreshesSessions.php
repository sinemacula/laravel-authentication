<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Sessions\RefreshCredential;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;

/**
 * The session service's refresh methods.
 *
 * Kept in a trait only to hold the service under the per-class method limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RefreshesSessions
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionRefresh Exchanges refresh tokens and binds the refreshed sessions, on the guard's context. */
    private readonly SessionRefresh $refreshes;

    /**
     * Exchange the refresh token presented for a new access token and a rotated
     * refresh token, and bind the guard to the refreshed session; `null` when
     * nothing was presented.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  int|string|null  $expectedSession
     * @return ($presented is null ? null : \SineMacula\Laravel\Authentication\Sessions\RefreshResult)
     *
     * @throws \Throwable
     */
    public function refresh(
        #[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented,
        ClientContext $client,
        int|string|null $expectedSession = null,
    ): ?RefreshResult {
        return $this->refreshes->refresh($presented, $client, $expectedSession);
    }

    /**
     * Who the presented refresh credential would sign in again, without
     * rotating it or binding anything, or why it is refused.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Sessions\RefreshCredential|null
     *
     * @throws \Throwable
     *
     * @internal
     */
    public function refreshCredential(#[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented, ClientContext $client): FailureReason|RefreshCredential|null
    {
        return $this->refreshes->credential($presented, $client);
    }
}
