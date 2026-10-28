<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonInterface;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\Integration\Fixtures\CutoffIdentity;

/**
 * Performance contract for "tokens valid after" on the bearer path: the time is
 * read from the identity the bearer path already loaded, so a device-less token
 * of an identity that records one costs the same single read as any other,
 * accepted or rejected.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BearerAuthentication::class)]
final class TokensValidAfterQueryBudgetTest extends PerformanceContractTestCase
{
    /**
     * Create the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('cutoff_identities');

        parent::tearDown();
    }

    /**
     * A token issued after the time is accepted with the one identity read.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testAnAcceptedTokenCostsOneRead(): void
    {
        $guard = $this->guardFor($this->now->copy()->subMinute());

        self::assertTrue($this->assertQueryBudget(1, 0, static fn (): bool => $guard->check()));
    }

    /**
     * A token issued at the time is rejected with the same one read.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testARejectedTokenCostsOneRead(): void
    {
        $guard = $this->guardFor($this->now);

        self::assertFalse($this->assertQueryBudget(1, 0, static fn (): bool => $guard->check()));
    }

    /**
     * Configure the `api` guard over the identities that record a time.
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

        $config->set('auth.providers.cutoff', ['driver' => 'model', 'model' => CutoffIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'cutoff']);
    }

    /**
     * A fresh guard serving a device-less token, issued now, of an identity
     * that records the given time.
     *
     * @param  \Carbon\CarbonInterface  $time
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    private function guardFor(CarbonInterface $time): JwtGuard
    {
        $identity = CutoffIdentity::query()->create(['email' => 'ada@example.test', 'password' => 'x', 'tokens_valid_after' => $time]);
        $tokens   = PackageAuth::jwt('api');

        self::assertNotNull($tokens);

        $this->bindRequestWithBearer('/me', $tokens->issueAccessToken($identity, $identity, null));

        return $this->freshJwtGuard('api');
    }
}
