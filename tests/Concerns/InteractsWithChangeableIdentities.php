<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonInterface;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\Integration\Fixtures\ChangeableMachine;
use Tests\Integration\Fixtures\VerifiableIdentity;

/**
 * Shared set-up for tests that change identifiers through the package's guards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithChangeableIdentities
{
    use InteractsWithCodes, InteractsWithSessionRecords, InteractsWithSessions;

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
     * Create the `changeable_identities` table on the given or default
     * connection.
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
            $blueprint->boolean('is_active')->default(true);
            $blueprint->datetimes(0);

            if (!$unique) {
                return;
            }

            $email->unique();
            $phone->unique();
        });
    }

    /**
     * Drop the `changeable_identities` table from the given or default
     * connection.
     *
     * @param  ?string  $connection
     * @return void
     */
    protected static function dropChangeableIdentitiesTable(?string $connection = null): void
    {
        Schema::connection($connection)->dropIfExists('changeable_identities');
    }

    /**
     * Register the providers and guards, a sync queue, a cheap password hash
     * and a short timebox.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected static function configureChangeGuards(ConfigRepository $config): void
    {
        $application = ['methods' => ['password', 'email_code', 'phone_code']];

        $config->set('auth.providers.changeables', ['driver' => 'model', 'model' => ChangeableIdentity::class]);
        $config->set('auth.providers.changeable_machines', ['driver' => 'model', 'model' => ChangeableMachine::class]);
        $config->set('auth.providers.verifiables', ['driver' => 'model', 'model' => VerifiableIdentity::class]);
        $config->set('auth.guards.web', ['driver' => 'jwt', 'provider' => 'changeables', 'application' => $application]);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'provider' => 'changeables', 'application' => $application]);
        $config->set('auth.guards.machines', ['driver' => 'jwt', 'provider' => 'changeable_machines', 'application' => $application]);
        $config->set('auth.guards.verifiable', ['driver' => 'jwt', 'provider' => 'verifiables', 'application' => $application]);

        $config->set('queue.default', 'sync');
        $config->set('queue.connections.sync', ['driver' => 'sync']);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist an identity with the verified email and phone and the shared
     * password.
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
     * Persist a live session of the identity for the guard.
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @param  string  $guard
     * @param  ?\Carbon\CarbonInterface  $signedInAt
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    protected static function seedSession(ChangeableIdentity $identity, string $guard = 'web', ?CarbonInterface $signedInAt = null): Session
    {
        $session = new Session;

        $session->forceFill([
            ...self::liveSession($guard, $identity),
            'signed_in_at'         => $signedInAt ?? Carbon::now(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(),
        ])->save();

        return $session;
    }

    /**
     * Return the identifier change service of a freshly resolved guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService
     */
    protected function changes(string $guard = 'web'): IdentifierChangeService
    {
        $this->freshGuard($guard);

        return Auth::manager()->identifierChanges($guard);
    }

    /**
     * Proof of a recent authentication by a session of the identity that signed
     * in just now.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\Reauthentication
     */
    protected static function freshSession(Identity&Model $identity, string $guard = 'web'): Reauthentication
    {
        $session = new Session;

        $session->forceFill([
            ...self::sessionEndingAt(Carbon::now()->addDays(90), Carbon::now()->addDays(180), $guard),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => IdentifierCoercion::stringify($identity->getKey()),
        ])->save();

        return Reauthentication::session($session);
    }
}
