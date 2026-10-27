<?php

declare(strict_types = 1);

namespace Tests\Feature\Http;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Http\UnauthenticatedResponse;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Feature tests for the package guards' `401` guest response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnauthenticatedResponse::class)]
final class UnauthenticatedResponseTest extends TestCase
{
    /**
     * An exception raised for package guards renders as `401` with the
     * exception's message.
     *
     * @return void
     */
    public function testRendersUnauthorizedForPackageGuards(): void
    {
        $response = $this->responder()(new AuthenticationException('Token expired.', ['api', 'api_secondary']));

        self::assertNotNull($response);
        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['message' => 'Token expired.'], $response->getData(true));
    }

    /**
     * An exception raised for any non-package guard, alone or alongside a
     * package guard, defers to Laravel.
     *
     * @return void
     */
    public function testDefersToLaravelWhenAnyGuardIsNotAPackageGuard(): void
    {
        $responder = $this->responder();

        self::assertNull($responder(new AuthenticationException('Unauthenticated.', ['web'])));
        self::assertNull($responder(new AuthenticationException('Unauthenticated.', ['api', 'web'])));
    }

    /**
     * No guard names, or a `null` name, mean the default guard.
     *
     * @return void
     */
    public function testDefaultGuardDecidesWhenNoGuardIsNamed(): void
    {
        $responder = $this->responder();

        config()->set('auth.defaults.guard', 'api');

        self::assertTrue($responder->appliesTo([]));
        self::assertTrue($responder->appliesTo([null]));

        config()->set('auth.defaults.guard', 'web');

        self::assertFalse($responder->appliesTo([]));
        self::assertFalse($responder->appliesTo([null]));
    }

    /**
     * Configure two package guards beside Laravel's `web` session guard.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        foreach (['api', 'api_secondary'] as $guard) {
            $config->set('auth.guards.' . $guard, [
                'driver'   => 'jwt',
                'provider' => 'identities',
            ]);
        }
    }

    /**
     * Resolve the guest response from the container.
     *
     * @return \SineMacula\Laravel\Authentication\Http\UnauthenticatedResponse
     */
    private function responder(): UnauthenticatedResponse
    {
        return app(UnauthenticatedResponse::class);
    }
}
