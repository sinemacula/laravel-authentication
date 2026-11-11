<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\ClientCredentials\Enums\ClientAuthentication;
use SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignOutResult;

/**
 * Builds the plain values a controller hands on to the package's services from
 * the request it serves.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait BuildsPlainValues
{
    /**
     * The client of the given or served request, as a controller hands it on.
     *
     * @param  ?\Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    protected static function requestClient(?Request $request = null): ClientContext
    {
        return ClientContext::fromRequest($request ?? self::servedRequest());
    }

    /**
     * The refresh token the given or served request carries, as the guard's
     * transport extracts it.
     *
     * @param  string  $guard
     * @param  ?\Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null
     */
    protected static function servedToken(string $guard = 'api', ?Request $request = null): FailureReason|PresentedRefreshToken|null
    {
        return self::transportOf($guard)->extract($request ?? self::servedRequest());
    }

    /**
     * The client a token request authenticated with HTTP Basic.
     *
     * @param  string  $clientId
     * @param  string  $clientSecret
     * @param  ?string  $scope
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient
     */
    protected static function basicClient(string $clientId, #[\SensitiveParameter] string $clientSecret, ?string $scope = null): PresentedClient
    {
        return new PresentedClient($clientId, $clientSecret, $scope, ClientAuthentication::BASIC);
    }

    /**
     * Sign the given or served request out as a controller does, by its access
     * token first and otherwise by its refresh credential.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionService  $sessions
     * @param  string  $guard
     * @param  ?\Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \Throwable
     */
    protected static function signOutServed(SessionService $sessions, string $guard = 'api', ?Request $request = null): SignOutResult
    {
        $request ??= self::servedRequest();
        $transport = self::transportOf($guard);

        if ($sessions->signOut()) {
            return SignOutResult::signedOut(null, $transport->usesCookie() ? $transport->forgetCookie() : null);
        }

        return $sessions->signOutWith($transport->extract($request), ClientContext::fromRequest($request));
    }

    /**
     * The sign-in context of the request the application serves now.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInContext
     */
    protected static function requestContext(): SignInContext
    {
        return SignInContext::fromRequest(self::servedRequest());
    }

    /**
     * The refresh token transport of the guard, from the configuration.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     */
    private static function transportOf(string $guard): RefreshTokenTransport
    {
        return RefreshTokenTransport::forGuard($guard, app(Repository::class));
    }

    /**
     * The request the application serves now.
     *
     * @return \Illuminate\Http\Request
     */
    private static function servedRequest(): Request
    {
        $request = app('request');

        self::assertInstanceOf(Request::class, $request);

        return $request;
    }
}
