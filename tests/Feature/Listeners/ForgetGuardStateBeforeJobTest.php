<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Auth\AuthManager as IlluminateAuthManager;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Listeners\ForgetGuardStateBeforeJob;

/**
 * Feature tests for the reset of the package guards before each queued job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ForgetGuardStateBeforeJob::class)]
final class ForgetGuardStateBeforeJobTest extends TestCase
{
    /**
     * Each job starts by resetting the package's auth manager's guards.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEachJobResetsThePackageGuards(): void
    {
        $manager = \Mockery::mock(AuthManager::class);
        $manager->shouldReceive('forgetGuardState')->once();

        $this->app?->instance('auth', $manager);

        (new ForgetGuardStateBeforeJob)();
    }

    /**
     * An application whose `auth` binding is not the package's manager is left
     * alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnotherAuthManagerIsLeftAlone(): void
    {
        $manager = \Mockery::mock(IlluminateAuthManager::class);
        $manager->shouldNotReceive('guard');

        $this->app?->instance('auth', $manager);

        (new ForgetGuardStateBeforeJob)();
    }
}
