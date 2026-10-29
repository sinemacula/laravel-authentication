<?php

declare(strict_types = 1);

namespace Tests\Integration\Process;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Listeners\ForgetGuardStateBeforeJob;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ObserveGuardJob;
use Tests\TestCase;

/**
 * End-to-end tests for jobs run on the `sync` connection inside a request: the
 * job runs in the request that dispatched it, so the package guards keep that
 * request's state, whether the job went to the `sync` connection because it is
 * the default or through `dispatchSync()` with another default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ForgetGuardStateBeforeJob::class)]
final class ForgetGuardStateBeforeJobTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A session the request has just started stays bound after a job it runs
     * through `dispatchSync()`, though the default connection is not `sync`,
     * and the job sees it.
     *
     * @return void
     */
    public function testASessionJustStartedOutlastsADispatchSyncJob(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        self::assertTrue($guard->sessions()->signIn('password', self::credentials())->isSignedIn());

        $device = $guard->device();

        ObserveGuardJob::dispatchSync();

        self::assertSame(['identity' => $identity->getKey()], app('observed.identity'));
        self::assertSame($identity->getKey(), $guard->id());
        self::assertNotNull($device);
        self::assertSame($device, $guard->device());
    }

    /**
     * A request that signed its device-less session out stays signed out after
     * a job it runs through `dispatchSync()`: the bearer token is not read
     * again.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASignedOutRequestStaysSignedOutAfterADispatchSyncJob(): void
    {
        $guard = $this->bearerGuard();

        self::assertNotNull($guard->user());

        $guard->logout();

        ObserveGuardJob::dispatchSync();

        self::assertSame(['identity' => null], app('observed.identity'));
        self::assertNull($guard->user());
    }

    /**
     * With `sync` as the default connection, a dispatched job runs in the
     * request too, and leaves the guards as the request had them.
     *
     * @return void
     */
    public function testTheSyncDefaultConnectionLeavesTheRequestsSessionBound(): void
    {
        config()->set('queue.default', 'sync');

        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        self::assertTrue($guard->sessions()->signIn('password', self::credentials())->isSignedIn());

        dispatch(new ObserveGuardJob);

        self::assertSame(['identity' => $identity->getKey()], app('observed.identity'));
        self::assertSame($identity->getKey(), $guard->id());
        self::assertNotNull($guard->device());

        $guard->logout();

        dispatch(new ObserveGuardJob);

        self::assertSame(['identity' => null], app('observed.identity'));
        self::assertNull($guard->user());
    }

    /**
     * Configure the guards and a default queue connection that is not `sync`.
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('queue.default', 'null');
        $config->set('queue.connections.null', ['driver' => 'null']);
    }

    /**
     * The `api` guard, resolved afresh for a request carrying a device-less
     * access token of a new identity.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Random\RandomException
     */
    private function bearerGuard(): JwtGuard
    {
        $identity = $this->seedIdentity();
        $tokens   = Auth::jwt('api');

        self::assertNotNull($tokens);

        $token = $tokens->issueAccessToken($identity, $identity, null);

        app()->instance('request', Request::create('/account', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        Auth::forgetGuards();

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard;
    }
}
