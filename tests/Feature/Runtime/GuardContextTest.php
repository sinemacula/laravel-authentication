<?php

declare(strict_types = 1);

namespace Tests\Feature\Runtime;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Resolvers\CountingPrincipalResolver;
use Tests\Fixtures\Resolvers\IdentityAsPrincipalResolver;
use Tests\TestCase;

/**
 * Feature tests of a guard's execution context: the one copy of the guard's
 * name, provider, resolver, dispatcher, request and timebox that every flow of
 * the guard reads, each time it uses one, so a rebind after a flow was built
 * reaches it, and that no other guard shares.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardContext::class)]
#[CoversClass(AbstractGuard::class)]
#[CoversClass(JwtGuard::class)]
final class GuardContextTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithSessions;

    /** @var string A password that is not the identity's. */
    private const string WRONG_PASSWORD = 'not the password';

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
     * The context holds what the guard was built with, under the guard's name,
     * and the guard reads and rebinds through it.
     *
     * @return void
     */
    public function testTheContextHoldsWhatTheGuardWasBuiltWith(): void
    {
        $guard   = $this->freshGuard();
        $context = $guard->context();

        self::assertSame('api', $context->name());
        self::assertSame($guard->getName(), $context->name());
        self::assertSame($guard->getProvider(), $context->provider());
        self::assertSame($guard->getPrincipalResolver(), $context->resolver());
        self::assertSame($guard->getDispatcher(), $context->events());
        self::assertSame(app('events'), $context->events());
        self::assertSame(app('request'), $context->request());
        self::assertSame(self::CLIENT_IP, $context->client()->ip);
        self::assertSame(self::CLIENT_AGENT, $context->client()->userAgent);
        self::assertSame($context->timebox(), $guard->context()->timebox());
        self::assertSame($context, $guard->context());
    }

    /**
     * An event dispatched through the context goes to the dispatcher the
     * context holds when it is dispatched.
     *
     * @return void
     */
    public function testAnEventDispatchedThroughTheContextReachesItsDispatcherAsItIsThen(): void
    {
        $guard = $this->freshGuard();
        $event = new \stdClass;

        $before = \Mockery::mock(Dispatcher::class);
        $before->shouldNotReceive('dispatch');

        $after = \Mockery::mock(Dispatcher::class);
        $after->shouldReceive('dispatch')->once()->with($event);

        $guard->setDispatcher($before);
        $guard->setDispatcher($after);

        $guard->context()->dispatch($event);

        self::assertSame($after, $guard->context()->events());
    }

    /**
     * A dispatcher swapped in after the guard resolved (`Event::fake()`)
     * receives the events of every flow of the guard, the services built before
     * the swap included: a sign-in, a code request, a passkey's removal, a
     * password reset, a refresh and a bearer request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADispatcherSwappedAfterTheGuardResolvedReachesEveryFlow(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);
        $guard    = $this->freshGuard();
        $session  = $guard->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $sessions  = $guard->sessions();
        $codes     = Auth::codes('api');
        $passkeys  = Auth::passkeys('api');
        $passwords = Auth::passwords('api');

        Event::fake();

        self::assertSame(Event::getFacadeRoot(), $guard->context()->events());

        self::assertNull($sessions->signIn('password', ['email' => 'ada@example.test', 'password' => self::WRONG_PASSWORD])->session);
        self::assertFalse($codes->send('email_code', ['email' => 'ada@example.test'])->isSent());
        self::assertTrue($passkeys->remove($identity, $passkey->id));
        self::assertFalse($passwords->reset(['email' => 'ada@example.test', 'token' => str_repeat('a', 43), 'password' => 'a brand new passphrase'])->isReset());
        self::assertInstanceOf(RefreshResult::class, $guard->refresh($session->tokens->refreshToken));

        $guard->setRequest(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer not-a-token']));

        self::assertNull($guard->user());

        Event::assertDispatched(AuthenticationFailed::class, static fn (AuthenticationFailed $event): bool => $event->flow === AuthenticationFlow::SIGN_IN);
        Event::assertDispatched(AuthenticationFailed::class, static fn (AuthenticationFailed $event): bool => $event->flow === AuthenticationFlow::CODE_REQUEST);
        Event::assertDispatched(PasskeyRemoved::class);
        Event::assertDispatched(AuthenticationFailed::class, static fn (AuthenticationFailed $event): bool => $event->flow === AuthenticationFlow::PASSWORD_RESET);
        Event::assertDispatched(Refreshed::class, static fn (Refreshed $event): bool => $event->context->guard === 'api');
        Event::assertDispatched(AuthenticationFailed::class, static fn (AuthenticationFailed $event): bool => $event->flow === AuthenticationFlow::BEARER);
    }

    /**
     * A request rebound after the guard's session service and its refresh
     * exchange were built reaches both: the sign-in reports the client of the
     * request it is made in, and so does a refresh after another rebind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestRebindReachesAFlowBuiltBeforeIt(): void
    {
        $this->seedIdentity();

        $guard    = $this->freshGuard();
        $sessions = $guard->sessions();

        $this->recordEvents([SignedIn::class, AuthenticationFailed::class]);

        app()->instance('request', Request::create('/sign-in', 'POST', server: ['REMOTE_ADDR' => '198.51.100.20', 'HTTP_USER_AGENT' => 'Rebound/1.0']));

        self::assertSame('198.51.100.20', $guard->context()->request()->ip());
        self::assertNotNull($sessions->signIn('password', self::credentials())->session);
        $client = $this->recordedEvent(SignedIn::class)->context->client;

        self::assertSame(['198.51.100.20', 'Rebound/1.0'], [$client->ip, $client->userAgent]);

        app()->instance('request', Request::create('/refresh', 'POST', server: ['REMOTE_ADDR' => '198.51.100.30']));

        self::assertNull($guard->refresh('not-a-token'));
        self::assertSame('198.51.100.30', $this->recordedEvent(AuthenticationFailed::class)->context->client->ip);
    }

    /**
     * A rebind of the global principal resolver reaches a guard that tracks it,
     * on refresh as on the guard itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGlobalResolverRebindReachesRefresh(): void
    {
        $this->seedIdentity();

        $guard   = $this->freshGuard();
        $session = $guard->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $resolver = new CountingPrincipalResolver;

        app()->instance(PrincipalResolver::class, $resolver);

        self::assertSame($resolver, $guard->context()->resolver());
        self::assertInstanceOf(RefreshResult::class, $guard->refresh($session->tokens->refreshToken));
        self::assertGreaterThan(0, $resolver->calls);
    }

    /**
     * A guard with a resolver of its own keeps it when the global resolver is
     * rebound: its refresh does not ask the global one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardLocalResolverIsNotReplaced(): void
    {
        $this->seedIdentity();

        $guard   = $this->freshGuard('local');
        $local   = $guard->context()->resolver();
        $session = $guard->sessions()->signIn('password', self::credentials())->session;

        self::assertInstanceOf(IdentityAsPrincipalResolver::class, $local);
        self::assertNotNull($session);

        $resolver = new CountingPrincipalResolver;

        app()->instance(PrincipalResolver::class, $resolver);

        self::assertSame($local, $guard->context()->resolver());
        self::assertInstanceOf(RefreshResult::class, $guard->refresh($session->tokens->refreshToken));
        self::assertSame(0, $resolver->calls);
    }

    /**
     * Two guards resolved in one process have a context each: a rebind of one
     * guard's dispatcher does not reach the other, and each guard's refresh
     * exchange is bound to that guard's context and token service, so one guard
     * does not take another's refresh token and reports its own name.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoGuardsInOneProcessNeverShareAContext(): void
    {
        $this->seedIdentity();
        $this->freshGuard();

        $api   = app('auth')->guard('api');
        $admin = app('auth')->guard('admin');

        self::assertInstanceOf(JwtGuard::class, $api);
        self::assertInstanceOf(JwtGuard::class, $admin);
        self::assertNotSame($api->context(), $admin->context());
        self::assertSame(['api', 'admin'], [$api->context()->name(), $admin->context()->name()]);
        self::assertSame($api->context()->request(), $admin->context()->request());
        self::assertNotSame($api->context()->timebox(), $admin->context()->timebox());

        $apiSession   = $api->sessions()->signIn('password', self::credentials())->session;
        $adminSession = $admin->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($apiSession);
        self::assertNotNull($adminSession);

        $this->recordEvents([Refreshed::class, AuthenticationFailed::class]);

        self::assertNull($api->refresh($adminSession->tokens->refreshToken));
        self::assertNull($admin->refresh($apiSession->tokens->refreshToken));
        self::assertSame(['api', 'admin'], array_map(static fn (AuthenticationFailed $event): ?string => $event->context->guard, $this->recorded));

        $silent = \Mockery::mock(Dispatcher::class);
        $silent->shouldNotReceive('dispatch');

        $api->setDispatcher($silent);

        $this->recordEvents([Refreshed::class]);

        self::assertInstanceOf(RefreshResult::class, $admin->refresh($adminSession->tokens->refreshToken));
        self::assertSame(['admin'], array_map(static fn (Refreshed $event): ?string => $event->context->guard, $this->recorded));
        self::assertNotSame($silent, $admin->context()->events());
    }

    /**
     * Configure the session guards, passkeys, and a guard with a principal
     * resolver of its own.
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
        self::configurePasskeys($config);

        $config->set('auth.guards.local', [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'audience'           => ['methods' => ['password']],
            'principal_resolver' => IdentityAsPrincipalResolver::class,
        ]);
    }
}
