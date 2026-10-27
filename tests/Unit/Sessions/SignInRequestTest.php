<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

/**
 * Unit tests for what a sign-in method is asked to verify.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInRequest::class)]
final class SignInRequestTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The request carries the guard, its provider, the input as sent, and the
     * client.
     *
     * @return void
     */
    public function testCarriesTheSignIn(): void
    {
        $provider = \Mockery::mock(IdentityProvider::class);
        $client   = new ClientContext('203.0.113.7', 'agent');

        $request = new SignInRequest('api', $provider, ['email' => 'ada@example.test', 'password' => 'secret'], $client);

        self::assertSame('api', $request->guard);
        self::assertSame($provider, $request->provider);
        self::assertSame(['email' => 'ada@example.test', 'password' => 'secret'], $request->input);
        self::assertSame($client, $request->client);
    }

    /**
     * A check counted through the request is the sign-in's: the request
     * reserves it on the account through the sign-in's account attempts, and
     * reports a refusal; a request built without them counts nothing.
     *
     * @return void
     */
    public function testAccountChecksAreCountedThroughTheSignInsAccountAttempts(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->twice()->andReturn(
            new AttemptReservation(new AttemptSubject('api', AttemptFlow::SIGN_IN, null, null, null), null),
            new AttemptReservation(new AttemptSubject('api', AttemptFlow::SIGN_IN, null, null, null), 30),
        );

        $provider = \Mockery::mock(IdentityProvider::class);
        $client   = new ClientContext('203.0.113.7', 'agent');
        $counted  = new SignInRequest('api', $provider, [], $client, (new AccountAttempts($limiter, 'api'))->reserve(...));

        self::assertTrue($counted->reserveAccountAttempt($identity));
        self::assertFalse($counted->reserveAccountAttempt($identity));
        self::assertTrue((new SignInRequest('api', $provider, [], $client))->reserveAccountAttempt($identity));
    }

    /**
     * A method's own test can build a request whose accounts have no attempts
     * left, with a callback that refuses, and see the identity it was asked
     * about.
     *
     * @return void
     */
    public function testARequestCanBeBuiltWhoseAccountsAreRefused(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $client   = new ClientContext('203.0.113.7', 'agent');
        $asked    = [];
        $refusing = new SignInRequest('api', \Mockery::mock(IdentityProvider::class), [], $client, static function (Identity $checked) use (&$asked): bool {
            $asked[] = $checked;

            return false;
        });

        self::assertFalse($refusing->reserveAccountAttempt($identity));
        self::assertSame([$identity], $asked);
    }

    /**
     * The input is a sensitive parameter, so a stack trace through the
     * constructor never shows the password.
     *
     * @return void
     */
    public function testInputIsASensitiveParameter(): void
    {
        $input = (new \ReflectionMethod(SignInRequest::class, '__construct'))->getParameters()[2];

        self::assertSame('input', $input->getName());
        self::assertNotEmpty($input->getAttributes(\SensitiveParameter::class));
    }
}
