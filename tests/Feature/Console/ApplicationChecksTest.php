<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Console\ApplicationChecks;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use Tests\TestCase;

/**
 * Feature tests of the application checks `authentication:check` runs for a
 * `jwt` guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationChecks::class)]
final class ApplicationChecksTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A custom policy is asked every name and then `client_secret_post`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testACustomPolicyIsAskedEveryNameAndClientSecretPost(): void
    {
        $asked  = [];
        $policy = \Mockery::mock(ApplicationPolicy::class);

        $policy->allows('allowsMethod')->andReturnUsing(static function (string $guard, string $method) use (&$asked): bool {
            $asked[] = "{$guard}:{$method}";

            return false;
        });
        $policy->expects('allowsClientSecretPost')->once()->with('api')->andReturnUsing(static function () use (&$asked): bool {
            $asked[] = 'api:client_secret_post';

            return false;
        });

        $this->app?->instance(ApplicationPolicy::class, $policy);

        $this->checks()->validate('api');

        $names = [...app(SignInMethodManager::class)->names(), 'external_provider', 'client_credentials', 'client_secret_post'];

        self::assertSame(array_map(static fn (string $name): string => "api:{$name}", $names), $asked);
    }

    /**
     * An exception a policy of the application's own throws when asked about
     * `client_secret_post` reaches the caller, which reports it for the guard.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testACustomPolicyThatCannotAnswerClientSecretPostThrows(): void
    {
        $policy = \Mockery::mock(ApplicationPolicy::class);

        $policy->allows('allowsMethod')->andReturnTrue();
        $policy->allows('allowsClientSecretPost')->andThrow(new \InvalidArgumentException('Unreadable `client_secret_post` setting.'));

        $this->app?->instance(ApplicationPolicy::class, $policy);

        $this->expectExceptionObject(new \InvalidArgumentException('Unreadable `client_secret_post` setting.'));

        $this->checks()->validate('api');
    }

    /**
     * The package's policy validates the guard's settings instead of being
     * asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThePackagePolicyValidatesTheGuardsSettings(): void
    {
        config()->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users', 'application' => ['client_secret_post' => true]]);

        $this->checks()->validate('api');

        config()->set('auth.guards.api.application.client_secret_post', 'yes');

        $this->expectExceptionObject(new \InvalidArgumentException('Application `client_secret_post` for guard [api] must be true or false: '
            . 'set `authentication.application.client_secret_post` or the guard\'s `application.client_secret_post` override.'));

        $this->checks()->validate('api');
    }

    /**
     * The checks, over the application's container and configuration.
     *
     * @return \SineMacula\Laravel\Authentication\Console\ApplicationChecks
     */
    private function checks(): ApplicationChecks
    {
        return new ApplicationChecks(app(), config());
    }
}
