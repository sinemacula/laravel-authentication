<?php

declare(strict_types = 1);

namespace Tests\Integration\Providers;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Fixtures\Resolvers\IdentityAsPrincipalResolver;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubReplacementPrincipalResolver;

/**
 * The policies another package binds hold whichever order the providers
 * register in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class SiblingPoliciesTestCase extends TestCase
{
    use InteractsWithMachineCredentials;

    /** @var string Password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Create the tables and freeze the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));
    }

    /**
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropMachineTables();

        self::releaseMachineClock();

        parent::tearDown();
    }

    /**
     * The sibling's additional-factor policy makes a sign-in wait for a further
     * factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSiblingsFactorPolicyAsksAFactorOfASignIn(): void
    {
        $identity            = new IntegrationIdentity;
        $identity->email     = 'ada@example.test';
        $identity->password  = app(Hasher::class)->make(self::PASSWORD);
        $identity->is_active = true;
        $identity->save();

        $this->startMachineRequest();

        $result = Auth::sessions('api')->signIn(
            'password',
            ['email' => 'ada@example.test', 'password' => self::PASSWORD],
            new SignInContext(new ClientContext(self::MACHINE_IP, self::MACHINE_AGENT)),
        );

        static::assertTrue($result->isPending(), 'Expected the sign-in to wait for a factor; got ' . $result->status->value);
        static::assertSame([PendingRequirement::MFA], $result->pending?->requires);
        static::assertSame(1, Session::query()->where('status', 'pending')->count());
        static::assertSame(0, Session::query()->where('status', 'active')->count());
    }

    /**
     * The sibling's scope registry refuses a scope an API key is issued with.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSiblingsScopeRegistryRefusesAScope(): void
    {
        $machine = $this->seedMachine();

        try {
            $this->apiKeys()->issue($machine, $machine, ['reports:read', 'admin']);

            static::fail('Expected the sibling\'s registry to refuse the scope.');
        } catch (InvalidScopeException $exception) {
            static::assertSame(['admin'], $exception->scopes);
        }

        static::assertSame(0, DB::table('api_keys')->count());
    }

    /**
     * A guard resolves principals through the sibling's resolver and follows a
     * later rebind.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testTheGuardsResolveThroughTheSiblingsResolverAndFollowARebind(): void
    {
        $this->startMachineRequest();

        $guard = app('auth')->guard('api');

        static::assertInstanceOf(JwtGuard::class, $guard);
        static::assertInstanceOf(IdentityAsPrincipalResolver::class, self::resolverOf($guard));

        $replacement = new StubReplacementPrincipalResolver;

        app()->instance(PrincipalResolver::class, $replacement);

        static::assertSame($replacement, self::resolverOf($guard));
    }

    /**
     * Configure the machine and session guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureMachineGuards($app->make(ConfigRepository::class));
    }

    /**
     * The principal resolver the guard holds.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @return mixed
     */
    private static function resolverOf(JwtGuard $guard): mixed
    {
        return $guard->getPrincipalResolver();
    }
}
