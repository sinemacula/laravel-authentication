<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonInterface;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\Integration\Fixtures\ChangeableMachine;
use Tests\Integration\Fixtures\VerifiableIdentity;

/**
 * Shared set-up for tests that change identifiers through the package's guards:
 * the `changeable_identities` table and its identities, their devices, and
 * guards over them, built on the session and code tests' helpers.
 *
 * Guards: `web` and `admin` are two jwt guards over `ChangeableIdentity` (each
 * allowing `password`, `email_code` and `phone_code`), `machines` one over
 * `ChangeableMachine`, and `verifiable` one over `VerifiableIdentity`, whose
 * identifiers can be verified but not changed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithChangeableIdentities
{
    use InteractsWithCodes, InteractsWithDevices, InteractsWithSessions;

    /** @var string The seeded identity's email address. */
    protected const string EMAIL = 'ada@example.test';

    /** @var string The address a change moves to. */
    protected const string NEW_EMAIL = 'ada@new.example.test';

    /** @var string The seeded identity's phone number, in E.164. */
    protected const string PHONE = '+447700900123';

    /** @var string The number a change moves to. */
    protected const string NEW_PHONE = '+447700900456';

    /** @var string The first code the engine issues. */
    protected const string CODE = '135790';

    /**
     * Create the `changeable_identities` table on the given connection, or the
     * default one, with a unique index on each identifier unless told not to.
     *
     * @param  ?string  $connection
     * @param  bool  $unique
     * @return void
     */
    protected static function createChangeableIdentitiesTable(?string $connection = null, bool $unique = true): void
    {
        Schema::connection($connection)->create('changeable_identities', static function (Blueprint $blueprint) use ($unique): void {
            $blueprint->increments('id');
            $email = $blueprint->string('email')->nullable();
            $blueprint->dateTime('email_verified_at', 0)->nullable();
            $phone = $blueprint->string('phone')->nullable();
            $blueprint->dateTime('phone_verified_at', 0)->nullable();
            $blueprint->string('password')->nullable();
            $blueprint->datetimes(0);

            if (!$unique) {
                return;
            }

            $email->unique();
            $phone->unique();
        });
    }

    /**
     * Drop the `changeable_identities` table from the given connection, or the
     * default one.
     *
     * @param  ?string  $connection
     * @return void
     */
    protected static function dropChangeableIdentitiesTable(?string $connection = null): void
    {
        Schema::connection($connection)->dropIfExists('changeable_identities');
    }

    /**
     * Register the providers and guards, a sync queue for deliveries, a cheap
     * password hash and a timebox short enough not to slow the suite.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected static function configureChangeGuards(ConfigRepository $config): void
    {
        $audience = ['methods' => ['password', 'email_code', 'phone_code']];

        $config->set('auth.providers.changeables', ['driver' => 'model', 'model' => ChangeableIdentity::class]);
        $config->set('auth.providers.changeable_machines', ['driver' => 'model', 'model' => ChangeableMachine::class]);
        $config->set('auth.providers.verifiables', ['driver' => 'model', 'model' => VerifiableIdentity::class]);
        $config->set('auth.guards.web', ['driver' => 'jwt', 'provider' => 'changeables', 'audience' => $audience]);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'provider' => 'changeables', 'audience' => $audience]);
        $config->set('auth.guards.machines', ['driver' => 'jwt', 'provider' => 'changeable_machines', 'audience' => $audience]);
        $config->set('auth.guards.verifiable', ['driver' => 'jwt', 'provider' => 'verifiables', 'audience' => $audience]);

        $config->set('queue.default', 'sync');
        $config->set('queue.connections.sync', ['driver' => 'sync']);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist an identity with the email address and phone number, each
     * verified, and the shared password.
     *
     * @param  ?string  $email
     * @param  ?string  $phone
     * @return \Tests\Integration\Fixtures\ChangeableIdentity
     */
    protected static function seedChangeable(?string $email = self::EMAIL, ?string $phone = null): ChangeableIdentity
    {
        return ChangeableIdentity::query()->create([
            'email'             => $email,
            'email_verified_at' => $email === null ? null : '2026-01-01 00:00:00',
            'phone'             => $phone,
            'phone_verified_at' => $phone === null ? null : '2026-01-01 00:00:00',
            'password'          => app(Hasher::class)->make(self::PASSWORD),
        ]);
    }

    /**
     * Persist a live device of the identity for the guard, signed in at the
     * time given (now by default).
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @param  string  $guard
     * @param  ?\Carbon\CarbonInterface  $signedInAt
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    protected static function seedDevice(ChangeableIdentity $identity, string $guard = 'web', ?CarbonInterface $signedInAt = null): Device
    {
        $device = new Device;

        $device->forceFill([
            ...self::liveSession($guard, $identity),
            'signed_in_at'         => $signedInAt ?? Carbon::now(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(),
        ])->save();

        return $device;
    }

    /**
     * Start a request from the test client and return the named guard's
     * identifier change service, on a guard resolved afresh for that request.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService
     */
    protected function changes(string $guard = 'web'): IdentifierChangeService
    {
        $this->freshGuard($guard);

        return Auth::manager()->identifierChanges($guard);
    }
}
