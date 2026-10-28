<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\Facades\Auth;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineAccount;
use Tests\Integration\Fixtures\MachineClient;
use Tests\Integration\Fixtures\MachineMembership;

/**
 * Shared set-up for tests of machine credentials: an `api_key` guard
 * (`machine`) over `MachineClient`, which acts as its own principal; an
 * `api_key` guard (`accounts`) over `MachineAccount`, whose principals are
 * typed memberships of activatable tenants; a `jwt` guard (`m2m`) over
 * `MachineClient` for client credentials; a `jwt` guard (`api`) over the human
 * `IntegrationIdentity`; the tables behind them; seeded identities; the request
 * a call comes from; and a record of the events dispatched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithMachineCredentials
{
    /** @var string IP address requests come from. */
    protected const string MACHINE_IP = '198.51.100.20';

    /** @var string User agent requests come with. */
    protected const string MACHINE_AGENT = 'MachineTest/1.0';

    /** @var list<object> Events of interest dispatched since recording began. */
    protected array $machineEvents = [];

    /**
     * Create the machine, account, membership, tenant and human identity
     * tables.
     *
     * @return void
     */
    protected function createMachineTables(): void
    {
        Schema::create('machine_clients', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('machine_accounts', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('machine_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('account_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->string('type')->default('service');
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

        Schema::create('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the tables `createMachineTables()` created.
     *
     * @return void
     */
    protected function dropMachineTables(): void
    {
        foreach (['machine_clients', 'machine_accounts', 'machine_memberships', 'activatable_tenants', 'integration_identities'] as $table) {
            Schema::dropIfExists($table);
        }
    }

    /**
     * Register the guards and providers.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected static function configureMachineGuards(ConfigRepository $config): void
    {
        $config->set('auth.providers.machines', ['driver' => 'model', 'model' => MachineClient::class]);
        $config->set('auth.providers.accounts', ['driver' => 'model', 'model' => MachineAccount::class]);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => IntegrationIdentity::class]);
        $config->set('auth.guards.machine', ['driver' => 'api_key', 'provider' => 'machines', 'audience' => ['methods' => ['api_key']]]);
        $config->set('auth.guards.accounts', ['driver' => 'api_key', 'provider' => 'accounts', 'audience' => ['methods' => ['api_key'], 'principal_types' => ['service']]]);
        $config->set('auth.guards.m2m', ['driver' => 'jwt', 'provider' => 'machines', 'audience' => ['methods' => ['client_credentials']]]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'audience' => ['methods' => ['password']]]);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist a machine client.
     *
     * @param  string  $email
     * @param  bool  $active
     * @return \Tests\Integration\Fixtures\MachineClient
     */
    protected function seedMachine(string $email = 'robot@example.test', bool $active = true): MachineClient
    {
        return MachineClient::query()->create(['email' => $email, 'is_active' => $active]);
    }

    /**
     * Persist a service account with one membership of an active tenant.
     *
     * @param  ?\Tests\Integration\Fixtures\ActivatableTenant  $tenant
     * @param  string  $type
     * @return array{0: \Tests\Integration\Fixtures\MachineAccount, 1: \Tests\Integration\Fixtures\MachineMembership, 2: \Tests\Integration\Fixtures\ActivatableTenant}
     */
    protected function seedAccount(?ActivatableTenant $tenant = null, string $type = 'service'): array
    {
        $tenant ??= ActivatableTenant::query()->create(['name' => 'Tenant', 'is_active' => true]);

        $account    = MachineAccount::query()->create(['name' => 'Reporting']);
        $membership = MachineMembership::query()->create(['account_id' => $account->getKey(), 'tenant_id' => $tenant->getKey(), 'type' => $type]);

        return [$account, $membership, $tenant];
    }

    /**
     * Start a request from the test client and return the named guard's API
     * keys, on a guard resolved afresh for that request.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService
     */
    protected function apiKeys(string $guard = 'machine'): ApiKeyService
    {
        $this->startMachineRequest();

        return Auth::apiKeys($guard);
    }

    /**
     * Bind a fresh request from the test client and forget the resolved guards.
     *
     * @param  ?string  $bearer
     * @return void
     */
    protected function startMachineRequest(?string $bearer = null): void
    {
        $server = ['REMOTE_ADDR' => self::MACHINE_IP, 'HTTP_USER_AGENT' => self::MACHINE_AGENT];

        if ($bearer !== null) {
            $server['HTTP_AUTHORIZATION'] = 'Bearer ' . $bearer;
        }

        app()->instance('request', Request::create('/machine', 'GET', server: $server));

        Auth::forgetGuards();
    }

    /**
     * Move every clock the package reads to the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    protected static function freezeMachineClockAt(CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }

    /**
     * Move every clock forward by the seconds.
     *
     * @param  int  $seconds
     * @return void
     */
    protected static function travelMachineClock(int $seconds): void
    {
        self::freezeMachineClockAt(CarbonImmutable::now()->addSeconds($seconds));
    }

    /**
     * Return every clock to the real time.
     *
     * @return void
     */
    protected static function releaseMachineClock(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;
    }

    /**
     * Record every dispatched event of the given classes, in order, starting
     * afresh.
     *
     * @param  list<class-string>  $classes
     * @return void
     */
    protected function recordMachineEvents(array $classes): void
    {
        $this->machineEvents = [];

        Event::listen($classes, function (object $event): void {
            $this->machineEvents[] = $event;
        });
    }

    /**
     * The recorded events of the class.
     *
     * @template TEvent of object
     *
     * @param  class-string<TEvent>  $class
     * @return list<TEvent>
     */
    protected function machineEventsOf(string $class): array
    {
        return array_values(array_filter($this->machineEvents, static fn (object $event): bool => $event instanceof $class));
    }
}
