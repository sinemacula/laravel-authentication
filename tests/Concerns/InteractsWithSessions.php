<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;

/**
 * Shared set-up for tests that sign in through the session service: a 2D guard
 * (`api`) over `IntegrationIdentity`, a second 2D guard (`admin`) over the same
 * identities, and a 3D guard (`members`) over `ActivatableTenantMember`, whose
 * memberships act within activatable tenants; the tables behind them; seeded
 * identities; the request a sign-in comes from; and a record of the events it
 * dispatches.
 *
 * A trait rather than a base class because the session tests extend different
 * base cases (the package `TestCase` and the performance contract case).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithSessions
{
    /** @var string Plaintext password of every seeded identity. */
    protected const string PASSWORD = 'correct horse battery staple';

    /** @var string IP address sign-ins come from. */
    protected const string CLIENT_IP = '203.0.113.7';

    /** @var string User agent sign-ins come with. */
    protected const string CLIENT_AGENT = 'SessionTest/1.0';

    /** @var list<object> Events of interest dispatched since recording began. */
    protected array $recorded = [];

    /** @var array<class-string, true> Event classes a recording listener is registered for. */
    private array $listening = [];

    /**
     * Create the identity, member, membership and tenant tables.
     *
     * @return void
     */
    protected function createSessionTables(): void
    {
        Schema::create('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('activatable_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        Schema::create('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::create('activatable_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the tables `createSessionTables()` created.
     *
     * @return void
     */
    protected function dropSessionTables(): void
    {
        foreach (['activatable_tenant_memberships', 'activatable_tenant_members', 'activatable_tenants', 'integration_identities'] as $table) {
            Schema::dropIfExists($table);
        }
    }

    /**
     * Register the guards and providers, each guard allowing the password
     * method and the `sso` and `trusted` methods the tests register, a cheap
     * password hash, and a timebox short enough not to slow the suite.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected static function configureSessionGuards(ConfigRepository $config): void
    {
        $audience = ['methods' => ['password', 'sso', 'trusted']];

        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => IntegrationIdentity::class]);
        $config->set('auth.providers.members', ['driver' => 'model', 'model' => ActivatableTenantMember::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'audience' => $audience]);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'provider' => 'identities', 'audience' => $audience]);
        $config->set('auth.guards.members', ['driver' => 'jwt', 'provider' => 'members', 'audience' => $audience]);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist a 2D identity.
     *
     * @param  string  $email
     * @param  bool  $active
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     */
    protected function seedIdentity(string $email = 'ada@example.test', bool $active = true): IntegrationIdentity
    {
        $identity            = new IntegrationIdentity;
        $identity->email     = $email;
        $identity->password  = app(Hasher::class)->make(self::PASSWORD);
        $identity->is_active = $active;
        $identity->save();

        return $identity;
    }

    /**
     * Persist a 3D member with one membership in an active tenant.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $email
     * @param  ?\Tests\Integration\Fixtures\ActivatableTenant  $tenant
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenantMember, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership, 2: \Tests\Integration\Fixtures\ActivatableTenant}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    protected function seedMember(string $email = 'member@example.test', ?ActivatableTenant $tenant = null): array
    {
        $tenant ??= ActivatableTenant::query()->create(['name' => 'Tenant', 'is_active' => true]);

        $member = ActivatableTenantMember::query()->create(['email' => $email, 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        $membership = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);

        return [$member, $membership, $tenant];
    }

    /**
     * Start a request from the test client and return the named guard's session
     * service, on a guard resolved afresh for that request.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    protected function sessions(string $guard = 'api'): SessionService
    {
        return self::sessionsOf($this->freshGuard($guard));
    }

    /**
     * The session service the auth manager builds for the guard, which must be
     * the guard the manager holds under its name.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    protected static function sessionsOf(JwtGuard $guard): SessionService
    {
        self::assertSame($guard, app('auth')->guard($guard->getName()));

        return Auth::sessions($guard->getName());
    }

    /**
     * Start a request from the test client and resolve the named guard afresh
     * for it.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    protected function freshGuard(string $guard = 'api'): JwtGuard
    {
        app()->instance('request', Request::create('/sign-in', 'POST', server: [
            'REMOTE_ADDR'     => self::CLIENT_IP,
            'HTTP_USER_AGENT' => self::CLIENT_AGENT,
        ]));

        Auth::forgetGuards();

        $resolved = app('auth')->guard($guard);

        self::assertInstanceOf(JwtGuard::class, $resolved);

        return $resolved;
    }

    /**
     * The password credentials of the identity with the email.
     *
     * @param  string  $email
     * @return array<string, string>
     */
    protected static function credentials(string $email = 'ada@example.test'): array
    {
        return ['email' => $email, 'password' => self::PASSWORD];
    }

    /**
     * Record every dispatched event of the given classes, in order, starting
     * afresh.
     *
     * @param  list<class-string>  $classes
     * @return void
     */
    protected function recordEvents(array $classes): void
    {
        $this->recorded = [];

        foreach ($classes as $class) {

            if (isset($this->listening[$class])) {
                continue;
            }

            $this->listening[$class] = true;

            Event::listen($class, function (object $event): void {
                $this->recorded[] = $event;
            });
        }
    }

    /**
     * The classes of the recorded events, in order.
     *
     * @return list<class-string>
     */
    protected function recordedClasses(): array
    {
        return array_map(static fn (object $event): string => $event::class, $this->recorded);
    }

    /**
     * The one recorded event of the class.
     *
     * @template TEvent of object
     *
     * @param  class-string<TEvent>  $class
     * @return TEvent
     */
    protected function recordedEvent(string $class): object
    {
        $matching = array_values(array_filter($this->recorded, static fn (object $event): bool => $event instanceof $class));

        self::assertCount(1, $matching, "Expected exactly one {$class}.");

        return $matching[0];
    }
}
