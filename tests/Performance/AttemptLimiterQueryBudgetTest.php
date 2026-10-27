<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\RateLimiting\RateLimitStore;

/**
 * Query-budget contracts for the attempt limiter on the paths every sign-in and
 * refresh takes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(RateLimitStore::class)]
final class AttemptLimiterQueryBudgetTest extends PerformanceContractTestCase
{
    /** @var string Guard the limits are configured on. */
    private const string GUARD = 'limited';

    /**
     * A sign-in in a window that already has attempts costs one statement per
     * counter, and giving its slots back one more each; nothing is read.
     *
     * @return void
     */
    public function testSignInWithExistingCountersIsOneStatementPerCounter(): void
    {
        $this->limiter()->acquire($this->signIn());

        $reservation = $this->assertQueryBudget(0, 2, fn (): mixed => $this->limiter()->acquire($this->signIn()));

        $this->assertQueryBudget(0, 2, fn () => $this->limiter()->release($reservation));
    }

    /**
     * The first attempt of a window creates each counter: an update that finds
     * nothing, then the insert.
     *
     * @return void
     */
    public function testFirstSignInCreatesEachCounter(): void
    {
        $this->assertQueryBudget(0, 4, fn (): mixed => $this->limiter()->acquire($this->signIn()));
    }

    /**
     * A refused sign-in stops at the full counter: its update, the insert that
     * finds it there, and the second update.
     *
     * @return void
     */
    public function testRefusedSignInStopsAtTheFullCounter(): void
    {
        for ($attempt = 0; $attempt < 2; $attempt++) {
            $this->limiter()->acquire($this->signIn());
        }

        $refused = $this->assertQueryBudget(0, 3, fn (): mixed => $this->limiter()->acquire($this->signIn()));

        self::assertFalse($refused->granted());
    }

    /**
     * A refresh that succeeds reads both counters in one query and writes
     * nothing; a failure adds one statement per counter.
     *
     * @return void
     */
    public function testRefreshCostsOneReadAndAFailureOneWritePerCounter(): void
    {
        $this->limiter()->recordFailure($this->refresh());

        self::assertNull($this->assertQueryBudget(1, 0, fn (): mixed => $this->limiter()->blocked($this->refresh())));

        $this->assertQueryBudget(0, 2, fn () => $this->limiter()->recordFailure($this->refresh()));
    }

    /**
     * Configure the guard's limits.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.guards.' . self::GUARD, [
            'driver'      => 'jwt',
            'provider'    => 'users',
            'rate_limits' => ['sign_in' => ['per_identifier' => ['max' => 2, 'decay_seconds' => 300]]],
        ]);
    }

    /**
     * The container's attempt limiter.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter
     */
    private function limiter(): AttemptLimiter
    {
        $limiter = $this->app?->make(AttemptLimiter::class);

        self::assertInstanceOf(AttemptLimiter::class, $limiter);

        return $limiter;
    }

    /**
     * A sign-in attempt with an identifier and an IP address.
     *
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject
     */
    private function signIn(): AttemptSubject
    {
        return new AttemptSubject(self::GUARD, AttemptFlow::SIGN_IN, 'ben@example.com', 'email', '203.0.113.7');
    }

    /**
     * A refresh of a device from an IP address.
     *
     * @return \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject
     */
    private function refresh(): AttemptSubject
    {
        return new AttemptSubject(self::GUARD, AttemptFlow::REFRESH, 'device-1', null, '203.0.113.7');
    }
}
