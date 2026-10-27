<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Http\ClientContext;
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
