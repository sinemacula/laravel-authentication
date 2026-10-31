<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Integration\Fixtures\CodeIdentity;
use Tests\Integration\Fixtures\IntegrationIdentity;

/**
 * Runtime benchmark fixtures for signing in through the session service: a
 * password sign-in, a sign-in by a one-time code sent to a phone number, and
 * the check of a one-time code on its own. Every package collaborator a sign-in
 * resolves (the sign-in method, the audience policy, the attempt limiter, which
 * writes its counters, the factor policy) is the package's own, from the
 * container. Passwords are checked with `PlainBenchHasher`, so the timings are
 * the package's work, not bcrypt's or Argon2's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SignInBenchHarness
{
    /** @var string Name of the guard signed in with a password. */
    private const string PASSWORD_GUARD = 'api';

    /** @var string Name of the guard signed in with a one-time code. */
    private const string CODE_GUARD = 'mobile';

    /** @var string Shared benchmark password. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Email address of the identity that signs in with its password. */
    private const string EMAIL = 'bench-sign-in@example.test';

    /** @var string The code every issued one-time code is. */
    private const string CODE = '135790';

    /** @var int Number of phone numbers with a live code, each code usable once. */
    private const int CODE_POOL_SIZE = 128;

    /** @var \Illuminate\Foundation\Application */
    private readonly Application $app;

    /** @var \SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver */
    private readonly DefaultPrincipalResolver $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher */
    private readonly Dispatcher $events;

    /** @var \Illuminate\Support\Timebox */
    private readonly Timebox $timebox;

    /** @var \SineMacula\Laravel\Authentication\Codes\OneTimeCodes */
    private readonly OneTimeCodes $codes;

    /** @var list<string> Phone numbers with a live sign-in code, for the code sign-in path. */
    private array $signInPhones = [];

    /** @var int Current index into the sign-in phone pool. */
    private int $signInIndex = 0;

    /** @var list<\SineMacula\Laravel\Authentication\Codes\CodeBinding> Verification bindings with a live code, for the code check path. */
    private array $checkBindings = [];

    /** @var int Current index into the check binding pool. */
    private int $checkIndex = 0;

    /**
     * Seed the sign-in fixtures, and check that each path reaches the outcome
     * it measures.
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function __construct()
    {
        $now = Carbon::createStrict(2026, 4, 10, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow(CarbonImmutable::instance($now));
        JWT::$timestamp = $now->getTimestamp();

        $this->app = PackageBenchApplication::create([
            self::PASSWORD_GUARD => ['driver' => 'jwt', 'provider' => 'identities', 'audience' => ['methods' => ['password']]],
            self::CODE_GUARD     => ['driver' => 'jwt', 'provider' => 'code_identities', 'audience' => ['methods' => ['phone_code']]],
        ]);

        $this->codes = new OneTimeCodes($this->app->make(Repository::class), static fn (): string => self::CODE);
        $this->app->instance(OneTimeCodes::class, $this->codes);

        $this->resolver = new DefaultPrincipalResolver;
        $this->events   = $this->app->make('events');
        $this->timebox  = new Timebox;

        BenchSchema::ensureIdentityTable('integration_identities');
        BenchSchema::ensureCodeIdentityTable();
        BenchSchema::ensureDeviceTable();
        BenchSchema::ensureRateLimitTable();
        BenchSchema::ensureOneTimeCodeTable();

        $this->seedFixtures();
        $this->assertEachPathReachesItsOutcome();
    }

    /**
     * Benchmark a password sign-in, which starts a session on a new device.
     *
     * @return void
     */
    public function runPasswordSignIn(): void
    {
        $this->passwordSignIn();
    }

    /**
     * Benchmark a sign-in by the one-time code sent to a phone number, which
     * uses the code up and starts a session on a new device.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function runCodeSignIn(): void
    {
        $phone = BenchOutcome::take('code sign-in', $this->signInPhones, $this->signInIndex++);

        $this->codeSignIn($phone);
    }

    /**
     * Benchmark the check of a correct one-time code verifying a phone number,
     * which uses the code up.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function runCodeCheck(): void
    {
        $binding = BenchOutcome::take('code check', $this->checkBindings, $this->checkIndex++);

        $this->codes->check($binding, self::CODE, CarbonImmutable::now());
    }

    /**
     * Seed the password identity, and the code identities with a live code for
     * each path that uses one up, plus one each for the set-up check.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function seedFixtures(): void
    {
        $identity            = new IntegrationIdentity;
        $identity->email     = self::EMAIL;
        $identity->password  = $this->app->make('hash')->make(self::PASSWORD);
        $identity->is_active = true;
        $identity->save();

        $now = CarbonImmutable::now();

        for ($index = 0; $index <= self::CODE_POOL_SIZE; $index++) {

            $phone = sprintf('+4477009%05d', $index);

            $holder = CodeIdentity::query()->create(['phone' => $phone, 'phone_verified_at' => $now, 'is_active' => true]);

            $this->codes->issue(CodeBinding::signIn(self::CODE_GUARD, 'phone', $phone), $now);
            $this->signInPhones[] = $phone;

            $binding = CodeBinding::verification(self::CODE_GUARD, 'phone', $phone, $holder);

            $this->codes->issue($binding, $now);
            $this->checkBindings[] = $binding;
        }
    }

    /**
     * Run each benchmarked path once and throw unless it reaches the outcome
     * its name describes: a password sign-in and a code sign-in each start a
     * session, and a correct code checks. The code paths use up codes outside
     * the benchmark's pools.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function assertEachPathReachesItsOutcome(): void
    {
        $phone   = array_pop($this->signInPhones);
        $binding = array_pop($this->checkBindings);

        BenchOutcome::assert('password sign-in', $this->passwordSignIn()->isSignedIn());
        BenchOutcome::assert('code sign-in', $phone !== null && $this->codeSignIn($phone)->isSignedIn());
        BenchOutcome::assert('code check', $binding !== null && $this->codes->check($binding, self::CODE, CarbonImmutable::now())->failure() === null);
    }

    /**
     * Sign the identity in with its password on a fresh guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     */
    private function passwordSignIn(): SignInResult
    {
        return $this->sessions(self::PASSWORD_GUARD, IntegrationIdentity::class)->signIn('password', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
    }

    /**
     * Sign the identity with the phone number in by its code on a fresh guard.
     *
     * @param  string  $phone
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     */
    private function codeSignIn(string $phone): SignInResult
    {
        return $this->sessions(self::CODE_GUARD, CodeIdentity::class)->signIn('phone_code', ['phone' => $phone, 'code' => self::CODE]);
    }

    /**
     * The session service of a fresh `jwt` guard over the model, serving a
     * sign-in request from the benchmark's client, built as the auth manager
     * builds one.
     *
     * @param  string  $name
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $model
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    private function sessions(string $name, string $model): SessionService
    {
        $provider = new ModelProvider($this->app->make('hash'), $model);
        $tokens   = $this->app->make(JwtTokenServiceFactory::class)->forGuard($name);

        $guard = new JwtGuard(
            $name,
            $provider,
            $this->resolver,
            $this->events,
            BenchRequest::client()->duplicate(server: ['REQUEST_URI' => '/bench/sign-in', 'REQUEST_METHOD' => Request::METHOD_POST]),
            $this->timebox,
            $tokens,
            static fn (GuardContext $context): RefreshTokenExchange => new RefreshTokenExchange($tokens, $context, BenchDatabase::connectionResolver(), static fn (): null => null),
            static fn (GuardContext $context): SessionRevocations => new SessionRevocations(
                $context,
                new DeviceRevocations(BenchDatabase::connectionResolver(), static fn (): null => null),
                Container::getInstance(),
            ),
            BenchRequest::refreshTransport(...),
        );

        return new SessionService($guard->context(), $guard, $tokens, Container::getInstance(), BenchDatabase::connectionResolver(), static fn (): null => null);
    }
}
